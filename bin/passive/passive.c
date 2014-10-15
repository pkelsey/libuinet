/*
 * Copyright (c) 2014 Patrick Kelsey. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef ENABLE_EXTRACT
#include <zlib.h>
#endif

#include <netinet/in.h>

#include "uinet_api.h"

#ifdef ENABLE_EXTRACT
#include "http_parser.h"
#endif

#define EV_STANDALONE 1
#define EV_UINET_ENABLE 1
#include <ev.h>

struct passive_context;
struct interface_config;


struct content_type {
	const char *type;
	const char *file_ext;
};

struct value_buffer {
#define MAX_VALUE_LENGTH 127
	char data[MAX_VALUE_LENGTH + 1];
	int index;
};

struct connection_context {
	char label[64];
	ev_uinet watcher;
	struct passive_context *server;
	uint64_t bytes_read;
	int verbose;
	struct connection_context *peer;

#ifdef ENABLE_EXTRACT
	http_parser *parser;
	http_parser_settings *parser_settings;
	uint8_t *buffer;
	size_t buffer_size;
	size_t buffer_count;
	size_t buffer_index;
	int ishead;

	int parsing_field;
	int skip_field;
	struct value_buffer *value;
	int skip_value;
#define MAX_FIELD_LENGTH 32
	char field[MAX_FIELD_LENGTH + 1];
	int field_index;
	struct value_buffer content_type;
	struct value_buffer content_encoding;
	int extract_body;
	int fd;
	int file_counter;
	char filename_prefix[64];
	int unknown_encoding;
	int inflate;
	z_stream zstrm;
#endif
};


struct passive_context {
	struct ev_loop *loop;
	struct uinet_socket *listener;
	ev_uinet listen_watcher;
	int verbose;
	struct interface_config *interface;
	int extract;
#define MAX_CONTENT_TYPES 16
	struct content_type *content_types[MAX_CONTENT_TYPES + 1];
};

struct interface_config {
	uinet_instance_t uinst;
	char *ifname;
	char alias[UINET_IF_NAMESIZE];
	unsigned int cdom;
	int thread_create_result;
	pthread_t thread;
	struct ev_loop *loop;
	int promisc;
	int type;
	int instance;
	char *alias_prefix;
	int do_tcpstats;
	uint64_t num_sockets;
	uint64_t max_accept_batch;
	int stats;
	uinet_if_t uif;
};

struct server_config {
	char *listen_addr;
	int listen_port;
	struct interface_config *interface;
	int verbose;
	struct passive_context *passive;
	int addrany;
	int extract;
	struct content_type *content_types[MAX_CONTENT_TYPES + 1];
	int num_content_types;
};


static __inline int imin(int a, int b) { return (a < b ? a : b); }


static struct content_type *known_content_types[] = {
	&(struct content_type){ "application/gzip", ".gz" },
	&(struct content_type){ "application/json", ".json" },
	&(struct content_type){ "application/octet-stream", ".bin" },
	&(struct content_type){ "application/pdf", ".pdf" },
	&(struct content_type){ "application/zip", ".zip" },
	&(struct content_type){ "image/gif", ".gif" },
	&(struct content_type){ "image/jpeg", ".jpg" },
	&(struct content_type){ "image/png", ".png" },
	&(struct content_type){ "text/html", ".html" },
	&(struct content_type){ "text/plain", ".txt" },
	&(struct content_type){ "text/xml", ".xml" },
	NULL
};


static void
print_tcp_state(struct uinet_socket *so, const char *label)
{
	struct uinet_tcp_info info;
	unsigned int optlen;
	int error;

	memset(&info, 0, sizeof(info));
	optlen = sizeof(info);

	if ((error = uinet_sogetsockopt(so, UINET_IPPROTO_TCP, UINET_TCP_INFO, &info, &optlen))) {
		printf("%s: could not get TCP state (%d)\n", label, error);
		return;
	}

	printf("========================================================================================\n");
	printf("%s: fsm_state=%u rtt_us=%u rttvar_us=%u\n", label, info.tcpi_state, info.tcpi_rtt, info.tcpi_rttvar);
	printf("%s: snd mss=%u wscale=%u wnd=%u seq_nxt=%u retrans=%u zerowin=%u\n", label,
	       info.tcpi_snd_mss, info.tcpi_snd_wscale, info.tcpi_snd_wnd, info.tcpi_snd_nxt, info.tcpi_snd_rexmitpack, info.tcpi_snd_zerowin);
	printf("%s: snd ssthresh=%u cwnd=%u\n", label, info.tcpi_snd_ssthresh, info.tcpi_snd_cwnd);
	printf("%s: rcv mss=%u wscale=%u wnd=%u seq_nxt=%u ooo=%u\n", label,
	       info.tcpi_rcv_mss, info.tcpi_rcv_wscale, info.tcpi_rcv_space, info.tcpi_rcv_nxt, info.tcpi_rcv_ooopack);
	printf("========================================================================================\n");
}


static void
destroy_conn(struct connection_context *conn)
{
	ev_uinet *w  = &conn->watcher;

	ev_uinet_stop(conn->server->loop, w);
	ev_uinet_detach(w->ctx);
	uinet_soclose(w->so);
#ifdef ENABLE_EXTRACT
	if (conn->buffer)
		free(conn->buffer);
	if (conn->parser)
		free(conn->parser);
#endif
	conn->server->interface->num_sockets--;
	free(conn);
}


static void
passive_receive_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct connection_context *conn = (struct connection_context *)w->data;
#define BUFFER_SIZE (64*1024)
	uint8_t buffer[BUFFER_SIZE];
	struct uinet_iovec iov;
	struct uinet_uio uio;
	int max_read;
	int read_size;
	int bytes_read;
	int error;
	int flags;
	int i;
	int print_threshold = 10;
	int printable;
	int skipped;

	max_read = uinet_soreadable(w->so, 0);
	if (max_read <= 0) {
		/* the watcher should never be invoked if there is no error and there no bytes to be read */
		assert(max_read != 0);
		if (conn->verbose)
			printf("%s: can't read, closing\n", conn->label);
		goto err;
	} else {
		read_size = imin(max_read, BUFFER_SIZE - 1);

		uio.uio_iov = &iov;
		iov.iov_base = buffer;
		iov.iov_len = read_size;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = read_size;
		flags = UINET_MSG_HOLE_BREAK;

		error = uinet_soreceive(w->so, NULL, &uio, &flags);
		if (0 != error) {
			printf("%s: read error (%d), closing\n", conn->label, error);
			goto err;
		}

		bytes_read = read_size - uio.uio_resid;

		conn->bytes_read += bytes_read;

		if (conn->verbose > 2)
			print_tcp_state(w->so, conn->label);

		if (conn->verbose > 1) {

			printf("========================================================================================\n");
		}

		if (conn->verbose)
			printf("To %s (%u bytes, %llu total, %s)\n", conn->label, bytes_read,
			       (unsigned long long)conn->bytes_read, flags & UINET_MSG_HOLE_BREAK ? "HOLE" : "normal");
		
		if (conn->verbose > 1) {
			buffer[bytes_read] = '\0';
			printf("----------------------------------------------------------------------------------------\n");
			skipped = 0;
			printable = 0;
			for (i = 0; i < bytes_read; i++) {
				if ((buffer[i] >= 0x20 && buffer[i] <= 0x7e) || buffer[i] == 0x0a || buffer[i] == 0x0d || buffer[i] == 0x09) {
					printable++;
				} else {
					/*
					 * Print on printable-to-unprintable
					 * transition if enough consecutive
					 * printable chars were seen.
					 */
					if (printable >= print_threshold) {
						if (skipped) {
							printf("<%u>", skipped);
						}
						buffer[i] = '\0';
						printf("%s", &buffer[i - printable]);
					} else {
						skipped += printable;
					}
					printable = 0;
					skipped++;
				}
			}
			if (skipped) {
				printf("<%u>", skipped);
			}
			buffer[i] = '\0';
			printf("%s", &buffer[i - printable]);
			printf("\n");
			printf("========================================================================================\n");
		}
	}

	return;

err:
	destroy_conn(conn);
}

#ifdef ENABLE_EXTRACT
static void
passive_extract_parse_buffer(struct connection_context *conn)
{
	size_t bytes_to_end_of_buffer;
	size_t nparsed;

	while (conn->buffer_count && (HTTP_PARSER_ERRNO(conn->parser) == HPE_OK)) {
		bytes_to_end_of_buffer = conn->buffer_size - conn->buffer_index;
		nparsed = http_parser_execute(conn->parser, conn->parser_settings,
					      (char *)&conn->buffer[conn->buffer_index],
					      imin(conn->buffer_count, bytes_to_end_of_buffer));
		conn->buffer_count -= nparsed;
		conn->buffer_index += nparsed;
		if (conn->buffer_index == conn->buffer_size)
			conn->buffer_index = 0;
	}
}


/*
 * The passive http extraction code works by alternately parsing the
 * passively reconstructed request and response streams.  The same callback
 * (below) is used to drive the parsing of each stream.  Parsing begins with
 * the request stream, and once a complete request has been parsed, the
 * parser and read watcher for the request stream are paused and the parser
 * and read watcher for the response stream are activated.  Once an entire
 * response is parsed, the parser and read watcher for the response stream
 * are paused, and the parser and read watcher for the request stream are
 * activated.  Along the way, response bodies that match the supplied list
 * of content types are extracted to files.
 *
 * This is example code whose purpose is to demonstrate upper layer protocol
 * processing using libuinet passive sockets functionality.  Little to no
 * attempt is made to deal with a number of ugly realities involved in
 * robustly parsing http streams in the wild.
 */
static void
passive_extract_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct connection_context *conn = (struct connection_context *)w->data;
	struct uinet_iovec iov;
	struct uinet_uio uio;
	int max_read;
	int read_size;
	int bytes_read;
	int error;
	int flags;
	size_t nparsed;

	max_read = uinet_soreadable(w->so, 0);
	if (max_read <= 0) {
		/* the watcher should never be invoked if there is no error and there no bytes to be read */
		assert(max_read != 0);

		/*
		 * There are no more complete requests/responses to be had, shut everything down.
		 */
		if (conn->verbose)
			printf("%s: can't read, closing\n", conn->label);
		goto err;
	} else {
		read_size = imin(max_read, conn->buffer_size - conn->buffer_index);

		uio.uio_iov = &iov;
		iov.iov_base = &conn->buffer[conn->buffer_index];
		iov.iov_len = read_size;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = read_size;
		flags = UINET_MSG_HOLE_BREAK;

		error = uinet_soreceive(w->so, NULL, &uio, &flags);
		if (0 != error) {
			printf("%s: read error (%d), closing\n", conn->label, error);
			goto err;
		}

		if (flags & UINET_MSG_HOLE_BREAK) {
			printf("%s: hole in data, closing connections\n", conn->label);
			goto err;
		}

		bytes_read = read_size - uio.uio_resid;
		conn->buffer_count += bytes_read;
		conn->bytes_read += bytes_read;
		
		do {
			passive_extract_parse_buffer(conn);

			if (HTTP_PARSER_ERRNO(conn->parser) != HPE_OK) {
				if (HTTP_PARSER_ERRNO(conn->parser) == HPE_PAUSED) {
					if (conn->verbose > 1)
						printf("%s: completed parsing request or response\n", conn->label);
					http_parser_pause(conn->peer->parser, 0);
					passive_extract_parse_buffer(conn->peer);
					if (HTTP_PARSER_ERRNO(conn->peer->parser) == HPE_OK) {
						if (conn->verbose > 1)
							printf("%s: peer needs more data\n", conn->label);
						/* Peer parser needs more data */
						ev_uinet_stop(conn->server->loop, &conn->watcher);
						ev_uinet_start(conn->server->loop, &conn->peer->watcher);
						break;
					} else if (HTTP_PARSER_ERRNO(conn->peer->parser) != HPE_PAUSED) {
						printf("Peer parse failure %s, closing connections\n",
						       http_errno_name(HTTP_PARSER_ERRNO(conn->peer->parser)));
						goto err;
					} else {
						if (conn->verbose > 1)
							printf("%s: peer completed parsing request or response\n", conn->label);
						/*
						 * The other parser has paused, so it's time for us to continue
						 * parsing/receiving.
						 */
						http_parser_pause(conn->parser, 0);
					}
				} else {
					printf("Parse failure %s, closing connections\n",
					       http_errno_name(HTTP_PARSER_ERRNO(conn->parser)));
					goto err;
				}
			}
		} while (conn->buffer_count);
	}

	return;
err:
	/*
	 * Deliver EOS to each parser.  If a parser is paused or otherwise
	 * in an error state, no work will be done.  The main reason for
	 * doing this is to correctly handle the case where response parsing
	 * requires an EOS to complete.  Under such circumstances, one of
	 * the calls below will complete the work.
	 */
	http_parser_execute(conn->parser, conn->parser_settings, NULL, 0);
	http_parser_execute(conn->peer->parser, conn->peer->parser_settings, NULL, 0);

	destroy_conn(conn->peer);
	destroy_conn(conn);
}


static int
on_http_req_message_begin(http_parser *parser)
{
	struct connection_context *conn = parser->data;

	conn->ishead = 0;

	return (0);
}


static int
on_http_req_message_complete(http_parser *parser)
{
	struct connection_context *conn = parser->data;

	if (conn->verbose)
		printf("%s: request type: %s\n", conn->label, http_method_str(parser->method));

	conn->ishead = (HTTP_HEAD == parser->method);

	/* 
	 * Exit the request parser so the response can be processed.  This
	 * protects the request state needed by the response parser from
	 * being overwritten early.
	 */
	http_parser_pause(parser, 1);

	return (0);
}


static int
on_http_resp_message_begin(http_parser *parser)
{
	struct connection_context *conn = parser->data;

	conn->extract_body = 0;
	conn->content_type.data[0] = '\0';
	conn->content_type.index = 0;
	conn->content_encoding.data[0] = '\0';
	conn->content_encoding.index = 0;

	return (0);
}


static int
on_http_resp_header_field(http_parser *parser, const char *at, size_t length)
{
	struct connection_context *conn = parser->data;

	if (!conn->parsing_field) {
		conn->parsing_field = 1;
		conn->skip_field = 0;
		conn->field_index = 0;
		if (conn->value) {
			conn->value->data[conn->value->index] = '\0';
		}
	}
	
	if (!conn->skip_field) {
		if (length <= (MAX_FIELD_LENGTH - conn->field_index)) {
			memcpy(&conn->field[conn->field_index], at, length);
			conn->field_index += length;
		} else {
			conn->skip_field = 1;
		}
	}
	return (0);
}


static int
on_http_resp_header_value(http_parser *parser, const char *at, size_t length)
{
	struct connection_context *conn = parser->data;

	if (conn->parsing_field) {
		conn->parsing_field = 0;
		conn->skip_value = 1;
		if (!conn->skip_field) {
			conn->field[conn->field_index] = '\0';
			if (strcasecmp(conn->field, "content-type") == 0) {
				conn->value = &conn->content_type;
				conn->value->index = 0;
				conn->skip_value = 0;
			} else if (strcasecmp(conn->field, "content-encoding") == 0) {
				conn->value = &conn->content_encoding;
				conn->value->index = 0;
				conn->skip_value = 0;
			}  
		}
	}

	if (!conn->skip_value) {
		if (length <= (MAX_VALUE_LENGTH - conn->value->index)) {
			memcpy(&conn->value->data[conn->value->index], at, length);
			conn->value->index += length;
		} else {
			conn->skip_value = 1;
		}
	}
	return (0);
}

static struct content_type *
find_content_type(const char *str, struct content_type *list[])
{
	while (*list) {
		if (strncasecmp(str, (*list)->type, strlen((*list)->type)) == 0)
			return *list;
		list++;
	}
	return (NULL);
}


static int
on_http_resp_headers_complete(http_parser *parser)
{
	struct connection_context *conn = parser->data;
	struct content_type *type;
	char filename[80];
	int offset;
	int thereisnobody;

	/* Ensure the last value stored is nul-terminated */
	if (conn->value)
		conn->value->data[conn->value->index] = '\0';

	if (conn->verbose) {
		    printf("%s: content type: %s\n", conn->label,
			   conn->content_type.index ? conn->content_type.data : "<unknown>");
		    printf("%s: content encoding: %s\n", conn->label,
			   conn->content_encoding.index ? conn->content_encoding.data : "identity");
	}

	if (conn->peer->ishead ||
	    parser->status_code / 100 == 1 || 
	    parser->status_code == 204 ||
	    parser->status_code == 304)  {
		thereisnobody = 1;
	} else {
		thereisnobody = 0;
		type = find_content_type(conn->content_type.data, conn->server->content_types);
		if (type)
			conn->extract_body = 1;
	}

	if (conn->extract_body) {
		conn->unknown_encoding = 0;
		conn->inflate = 0;
		if ((strcasecmp(conn->content_encoding.data, "x-gzip") == 0) ||
		    (strcasecmp(conn->content_encoding.data, "gzip") == 0) ||
		    (strcasecmp(conn->content_encoding.data, "deflate") == 0)) {
			conn->inflate = 1;
		} else if (conn->content_encoding.index > 0) {
			conn->unknown_encoding = 1;
		}

		if (conn->inflate) {
			conn->zstrm.zalloc = Z_NULL;
			conn->zstrm.zfree = Z_NULL;
			conn->zstrm.opaque = Z_NULL;
			conn->zstrm.avail_in = 0;
			conn->zstrm.next_in = Z_NULL;
			if (Z_OK != inflateInit2(&conn->zstrm, 32 + MAX_WBITS)) {
				conn->inflate = 0;
				conn->unknown_encoding = 1;
			}
		}

		snprintf(filename, sizeof(filename), "%s-%06d%s%s%s", conn->filename_prefix,
			 conn->file_counter, type->file_ext, conn->unknown_encoding ? "." : "",
			 conn->unknown_encoding ? conn->content_encoding.data : "");
		conn->file_counter++;
		conn->fd = open(filename, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR);
		if (-1 == conn->fd) {
			printf("%s: Failed to open %s for writing\n", conn->label, filename);
			conn->extract_body = 0;
			inflateEnd(&conn->zstrm);
		}
	}

	if (thereisnobody) {
		/* tell the parser there is no response body */
		return (1);
	} else {
		return (0);
	}
}


static int
on_http_resp_body(http_parser *parser, const char *at, size_t length)
{
	struct connection_context *conn = parser->data;
	uint8_t inflate_buffer[1024];
	int error;

	if (conn->verbose > 2)
		printf("%s: received %zu body bytes\n", conn->label, length);

	if (conn->extract_body) {
		if (conn->inflate) {
			conn->zstrm.avail_in = length;
			conn->zstrm.next_in = (unsigned char *)at;

			do {
				conn->zstrm.avail_out = sizeof(inflate_buffer);
				conn->zstrm.next_out = inflate_buffer;

				error = inflate(&conn->zstrm, Z_NO_FLUSH);
				if (error != Z_OK && error != Z_STREAM_END) {
					printf("%s: error while inflating %d, skipping rest of body\n", conn->label, error);
					inflateEnd(&conn->zstrm);
					conn->inflate = 0;
					conn->extract_body = 0;
					break;
				} else {
					write(conn->fd, inflate_buffer, sizeof(inflate_buffer) - conn->zstrm.avail_out);
				}
			} while (0 == conn->zstrm.avail_out);
		} else {
			write(conn->fd, at, length);
		}
	}

	return (0);
}


static int
on_http_resp_message_complete(http_parser *parser)
{
	struct connection_context *conn = parser->data;

	if (conn->verbose > 1)
		printf("%s: response complete\n", conn->label);

	if (conn->extract_body) {
		if (conn->inflate) {
			inflateEnd(&conn->zstrm);	
		}
		close(conn->fd);
	}

	/* 
	 * Exit the response parser so the next request can be processed.
	 */
	http_parser_pause(parser, 1);

	return (0);
}


static int
parser_init(struct connection_context *conn, enum http_parser_type type)
{
	http_parser *parser;
	http_parser_settings *parser_settings;

	parser = malloc(sizeof(*parser));
	if (NULL == parser)
		return (1);

	http_parser_init(parser, type);

	parser_settings = calloc(1, sizeof(*parser_settings));
	if (NULL == parser_settings) {
		free(parser);
		return (1);
	}

	if (HTTP_REQUEST == type) {
		parser_settings->on_message_begin = on_http_req_message_begin;
		parser_settings->on_message_complete = on_http_req_message_complete;
	} else {
		parser_settings->on_message_begin = on_http_resp_message_begin;
		parser_settings->on_header_field = on_http_resp_header_field;
		parser_settings->on_header_value = on_http_resp_header_value;
		parser_settings->on_headers_complete = on_http_resp_headers_complete;
		parser_settings->on_body = on_http_resp_body;
		parser_settings->on_message_complete = on_http_resp_message_complete;
	}

	parser->data = conn;
	conn->parser = parser;
	conn->parser_settings = parser_settings;

	return (0);
}
#endif /* ENABLE_EXTRACT */

static struct connection_context *
create_conn(struct passive_context *passive, struct uinet_socket *so, int server)
{
	struct connection_context *conn = NULL;
	struct ev_uinet_ctx *soctx = NULL;
	struct uinet_sockaddr_in *sin1, *sin2;
	char buf1[32], buf2[32];
	time_t now_timet;
	struct tm now;
#define EXTRACT_BUFFER_SIZE 1024

	conn = calloc(1, sizeof(*conn));
	if (NULL == conn) {
		printf("Failed to alloc connection context for new connection\n");
		goto fail;
	}

	soctx = ev_uinet_attach(so);
	if (NULL == soctx) {
		printf("Failed to alloc libev context for new connection socket\n");
		goto fail;
	}

	uinet_sogetsockaddr(so, (struct uinet_sockaddr **)&sin1);
	uinet_sogetpeeraddr(so, (struct uinet_sockaddr **)&sin2);
	snprintf(conn->label, sizeof(conn->label), "%s (%s:%u <- %s:%u)",
		 server ? "SERVER" : "CLIENT",
		 uinet_inet_ntoa(sin1->sin_addr, buf1, sizeof(buf1)), ntohs(sin1->sin_port),
		 uinet_inet_ntoa(sin2->sin_addr, buf2, sizeof(buf2)), ntohs(sin2->sin_port));
#ifdef ENABLE_EXTRACT
	if (passive->extract && !server) {
		time(&now_timet);
		localtime_r(&now_timet, &now);
		snprintf(conn->filename_prefix, sizeof(conn->filename_prefix),
			 "extract-%04d%02d%02d-%02d%02d.%02d-%s.%u-%s.%u",
			 now.tm_year + 1900, now.tm_mon + 1, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec,
			 uinet_inet_ntoa(sin1->sin_addr, buf1, sizeof(buf1)), ntohs(sin1->sin_port),
			 uinet_inet_ntoa(sin2->sin_addr, buf2, sizeof(buf2)), ntohs(sin2->sin_port));
	}
#endif
	uinet_free_sockaddr((struct uinet_sockaddr *)sin1);
	uinet_free_sockaddr((struct uinet_sockaddr *)sin2);

	conn->verbose = passive->verbose;
	conn->server = passive;
	if (passive->extract) {
#ifdef ENABLE_EXTRACT
		if (0 != parser_init(conn, server ? HTTP_REQUEST : HTTP_RESPONSE))
			goto fail;
		conn->buffer_size = EXTRACT_BUFFER_SIZE;
		conn->buffer = malloc(conn->buffer_size);
		if (NULL == conn->buffer)
			goto fail;
		ev_init(&conn->watcher, passive_extract_cb);
#else
		goto fail;
#endif
	} else {
		ev_init(&conn->watcher, passive_receive_cb);
	}
	ev_uinet_set(&conn->watcher, soctx, EV_READ);
	conn->watcher.data = conn;

	return (conn);

fail:
#ifdef ENABLE_EXTRACT
	if (conn->buffer) free(conn->buffer);
	if (conn->parser) free(conn->parser);
#endif
	if (conn) free(conn);
	if (soctx) ev_uinet_detach(soctx);

	return (NULL);
}


static void
accept_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct passive_context *passive = w->data;
	struct uinet_socket *newso = NULL;
	struct uinet_socket *newpeerso = NULL;
	struct connection_context *conn = NULL;
	struct connection_context *peerconn = NULL;
	int error;
	int batch_limit = 32;
	int processed = 0;

	while ((processed < batch_limit) &&
	       (UINET_EWOULDBLOCK != (error = uinet_soaccept(w->so, NULL, &newso)))) {
		processed++;

		if (0 == error) {
			newpeerso = NULL;
			conn = NULL;
			peerconn = NULL;

			if (passive->verbose)
				printf("accept succeeded\n");

			conn = create_conn(passive, newso, 1);
			if (NULL == conn)
				goto fail;

			newpeerso = uinet_sogetpassivepeer(newso);
			peerconn = create_conn(passive, newpeerso, 0);
			if (NULL == peerconn)
				goto fail;

			conn->peer = peerconn;
			peerconn->peer = conn;
			
			ev_uinet_start(loop, &conn->watcher);

			if (!passive->extract)
				ev_uinet_start(loop, &peerconn->watcher);

			passive->interface->num_sockets += 2;

			continue;
		fail:
			if (conn) destroy_conn(conn);
			if (newso) uinet_soclose(newso);
			if (newpeerso) uinet_soclose(newpeerso);
		}
	}

	if (processed > passive->interface->max_accept_batch)
		passive->interface->max_accept_batch = processed;
}


static struct passive_context *
create_passive(struct ev_loop *loop, struct server_config *cfg)
{
	struct passive_context *passive = NULL;
	struct uinet_socket *listener = NULL;
	struct ev_uinet_ctx *soctx = NULL;
	struct uinet_in_addr addr;
	int optlen, optval;
	int error;
	struct uinet_sockaddr_in sin;

	if (uinet_inet_pton(UINET_AF_INET, cfg->listen_addr, &addr) <= 0) {
		printf("Malformed address %s\n", cfg->listen_addr);
		goto fail;
	}

	error = uinet_socreate(cfg->interface->uinst, UINET_PF_INET, &listener, UINET_SOCK_STREAM, 0);
	if (0 != error) {
		printf("Listen socket creation failed (%d)\n", error);
		goto fail;
	}

	soctx = ev_uinet_attach(listener);
	if (NULL == soctx) {
		printf("Failed to alloc libev socket context\n");
		goto fail;
	}
	
	if ((error = uinet_make_socket_passive(listener))) {
		printf("Failed to make listen socket passive (%d)\n", error);
		goto fail;
	}

	if (cfg->interface->promisc) {
		if ((error = uinet_make_socket_promiscuous(listener, cfg->interface->cdom))) {
			printf("Failed to make listen socket promiscuous (%d)\n", error);
			goto fail;
		}
	}

	/* 
	 * The following settings will be inherited by all sockets created
	 * by this listen socket.
	 */

	/*
	 * Need to be non-blocking to work with the event system.
	 */
	uinet_sosetnonblocking(listener, 1);

	/* Wait 5 seconds for connections to complete */
	optlen = sizeof(optval);
	optval = 5;
	if ((error = uinet_sosetsockopt(listener, UINET_IPPROTO_TCP, UINET_TCP_KEEPINIT, &optval, optlen)))
		goto fail;

	/* Begin counting down to close after 10 seconds of idle */
	optlen = sizeof(optval);
	optval = 10;
	if ((error = uinet_sosetsockopt(listener, UINET_IPPROTO_TCP, UINET_TCP_KEEPIDLE, &optval, optlen)))
		goto fail;

	/* Count down to close once per second */
	optlen = sizeof(optval);
	optval = 1;
	if ((error = uinet_sosetsockopt(listener, UINET_IPPROTO_TCP, UINET_TCP_KEEPINTVL, &optval, optlen)))
		goto fail;

	/* Close after idle for 3 counts */
	optlen = sizeof(optval);
	optval = 3;
	if ((error = uinet_sosetsockopt(listener, UINET_IPPROTO_TCP, UINET_TCP_KEEPCNT, &optval, optlen)))
		goto fail;

	/* Wait 100 milliseconds for missing TCP segments */
	optlen = sizeof(optval);
	optval = 100;
	if ((error = uinet_sosetsockopt(listener, UINET_IPPROTO_TCP, UINET_TCP_REASSDL, &optval, optlen)))
		goto fail;



	passive = calloc(1, sizeof(struct passive_context));
	if (NULL == passive) {
		goto fail;
	}

	passive->loop = loop;
	passive->listener = listener;
	passive->verbose = cfg->verbose;
	passive->interface = cfg->interface;
	passive->extract = cfg->extract;
	memcpy(passive->content_types, cfg->content_types, sizeof(passive->content_types));

	memset(&sin, 0, sizeof(struct uinet_sockaddr_in));
	sin.sin_len = sizeof(struct uinet_sockaddr_in);
	sin.sin_family = UINET_AF_INET;
	sin.sin_addr = addr;
	sin.sin_port = htons(cfg->listen_port);
	error = uinet_sobind(listener, (struct uinet_sockaddr *)&sin);
	if (0 != error) {
		printf("bind failed\n");
		goto fail;
	}
	
	error = uinet_solisten(passive->listener, -1);
	if (0 != error)
		goto fail;

	if (passive->verbose) {
		char buf[32];

		printf("Listening on %s:%u\n", uinet_inet_ntoa(addr, buf, sizeof(buf)), cfg->listen_port);
	}

	ev_init(&passive->listen_watcher, accept_cb);
	ev_uinet_set(&passive->listen_watcher, soctx, EV_READ);
	passive->listen_watcher.data = passive;
	ev_uinet_start(loop, &passive->listen_watcher);

	return (passive);

fail:
	if (soctx) ev_uinet_detach(soctx);
	if (listener) uinet_soclose(listener);
	if (passive) free(passive);

	return (NULL);
}


static void
dump_ifstat(uinet_instance_t uinst, const char *name)
{
	struct uinet_ifstat stat;
	int perline = 3;
	int index = 1;

#define PRINT_IFSTAT(s) printf("%-26s= %-10lu%s", #s, stat.s, (index % perline == 0) ? "\n" : "  "); index++ 

	uinet_getifstat(uinst, name, &stat);

	printf("========================================================================\n");
	printf("%s:\n", name);

	PRINT_IFSTAT(ifi_ipackets);
	PRINT_IFSTAT(ifi_ierrors);
	PRINT_IFSTAT(ifi_opackets);
	PRINT_IFSTAT(ifi_oerrors);
	PRINT_IFSTAT(ifi_collisions);
	PRINT_IFSTAT(ifi_ibytes);
	PRINT_IFSTAT(ifi_obytes);
	PRINT_IFSTAT(ifi_imcasts);
	PRINT_IFSTAT(ifi_omcasts);
	PRINT_IFSTAT(ifi_iqdrops);
	PRINT_IFSTAT(ifi_noproto);
	PRINT_IFSTAT(ifi_hwassist);
	PRINT_IFSTAT(ifi_epoch);
	PRINT_IFSTAT(ifi_icopies);
	PRINT_IFSTAT(ifi_izcopies);
	PRINT_IFSTAT(ifi_ocopies);
	PRINT_IFSTAT(ifi_ozcopies);

	printf("\n");
	printf("========================================================================\n");


#undef PRINT_IFSTAT
}


static void
dump_tcpstat(uinet_instance_t uinst)
{
	struct uinet_tcpstat stat;
	int perline = 3;
	int index = 1;

#define PRINT_TCPSTAT(s) printf("%-26s= %-10lu%s", #s, stat.s, (index % perline == 0) ? "\n" : "  "); index++ 

	uinet_gettcpstat(uinst, &stat);

	printf("========================================================================\n");

	PRINT_TCPSTAT(tcps_connattempt);
	PRINT_TCPSTAT(tcps_accepts);
	PRINT_TCPSTAT(tcps_connects);
	PRINT_TCPSTAT(tcps_drops);
	PRINT_TCPSTAT(tcps_conndrops);
	PRINT_TCPSTAT(tcps_minmssdrops);
	PRINT_TCPSTAT(tcps_closed);
	PRINT_TCPSTAT(tcps_segstimed);
	PRINT_TCPSTAT(tcps_rttupdated);
	PRINT_TCPSTAT(tcps_delack);
	PRINT_TCPSTAT(tcps_timeoutdrop);
	PRINT_TCPSTAT(tcps_rexmttimeo);
	PRINT_TCPSTAT(tcps_persisttimeo);
	PRINT_TCPSTAT(tcps_keeptimeo);
	PRINT_TCPSTAT(tcps_keepprobe);
	PRINT_TCPSTAT(tcps_keepdrops);

	PRINT_TCPSTAT(tcps_sndtotal);
	PRINT_TCPSTAT(tcps_sndpack);
	PRINT_TCPSTAT(tcps_sndbyte);
	PRINT_TCPSTAT(tcps_sndrexmitpack);
	PRINT_TCPSTAT(tcps_sndrexmitbyte);
	PRINT_TCPSTAT(tcps_sndrexmitbad);
	PRINT_TCPSTAT(tcps_sndacks);
	PRINT_TCPSTAT(tcps_sndprobe);
	PRINT_TCPSTAT(tcps_sndurg);
	PRINT_TCPSTAT(tcps_sndwinup);
	PRINT_TCPSTAT(tcps_sndctrl);

	PRINT_TCPSTAT(tcps_rcvtotal);
	PRINT_TCPSTAT(tcps_rcvpack);
	PRINT_TCPSTAT(tcps_rcvbyte);
	PRINT_TCPSTAT(tcps_rcvbadsum);
	PRINT_TCPSTAT(tcps_rcvbadoff);
	PRINT_TCPSTAT(tcps_rcvmemdrop);
	PRINT_TCPSTAT(tcps_rcvshort);
	PRINT_TCPSTAT(tcps_rcvduppack);
	PRINT_TCPSTAT(tcps_rcvdupbyte);
	PRINT_TCPSTAT(tcps_rcvpartduppack);
	PRINT_TCPSTAT(tcps_rcvpartdupbyte);
	PRINT_TCPSTAT(tcps_rcvoopack);
	PRINT_TCPSTAT(tcps_rcvoobyte);
	PRINT_TCPSTAT(tcps_rcvpackafterwin);
	PRINT_TCPSTAT(tcps_rcvbyteafterwin);
	PRINT_TCPSTAT(tcps_rcvafterclose);
	PRINT_TCPSTAT(tcps_rcvwinprobe);
	PRINT_TCPSTAT(tcps_rcvdupack);
	PRINT_TCPSTAT(tcps_rcvacktoomuch);
	PRINT_TCPSTAT(tcps_rcvackpack);
	PRINT_TCPSTAT(tcps_rcvackbyte);
	PRINT_TCPSTAT(tcps_rcvwinupd);
	PRINT_TCPSTAT(tcps_pawsdrop);
	PRINT_TCPSTAT(tcps_predack);
	PRINT_TCPSTAT(tcps_preddat);
	PRINT_TCPSTAT(tcps_pcbcachemiss);
	PRINT_TCPSTAT(tcps_cachedrtt);
	PRINT_TCPSTAT(tcps_cachedrttvar);
	PRINT_TCPSTAT(tcps_cachedssthresh);
	PRINT_TCPSTAT(tcps_usedrtt);
	PRINT_TCPSTAT(tcps_usedrttvar);
	PRINT_TCPSTAT(tcps_usedssthresh);
	PRINT_TCPSTAT(tcps_persistdrop);
	PRINT_TCPSTAT(tcps_badsyn);
	PRINT_TCPSTAT(tcps_mturesent);
	PRINT_TCPSTAT(tcps_listendrop);
	PRINT_TCPSTAT(tcps_badrst);

	PRINT_TCPSTAT(tcps_sc_added);
	PRINT_TCPSTAT(tcps_sc_retransmitted);
	PRINT_TCPSTAT(tcps_sc_dupsyn);
	PRINT_TCPSTAT(tcps_sc_dropped);
	PRINT_TCPSTAT(tcps_sc_completed);
	PRINT_TCPSTAT(tcps_sc_bucketoverflow);
	PRINT_TCPSTAT(tcps_sc_cacheoverflow);
	PRINT_TCPSTAT(tcps_sc_reset);
	PRINT_TCPSTAT(tcps_sc_stale);
	PRINT_TCPSTAT(tcps_sc_aborted);
	PRINT_TCPSTAT(tcps_sc_badack);
	PRINT_TCPSTAT(tcps_sc_unreach);
	PRINT_TCPSTAT(tcps_sc_zonefail);
	PRINT_TCPSTAT(tcps_sc_sendcookie);
	PRINT_TCPSTAT(tcps_sc_recvcookie);

	PRINT_TCPSTAT(tcps_hc_added);
	PRINT_TCPSTAT(tcps_hc_bucketoverflow);

	PRINT_TCPSTAT(tcps_finwait2_drops);

	PRINT_TCPSTAT(tcps_sack_recovery_episode);
	PRINT_TCPSTAT(tcps_sack_rexmits);
	PRINT_TCPSTAT(tcps_sack_rexmit_bytes);
	PRINT_TCPSTAT(tcps_sack_rcv_blocks);
	PRINT_TCPSTAT(tcps_sack_send_blocks);
	PRINT_TCPSTAT(tcps_sack_sboverflow);
	
	PRINT_TCPSTAT(tcps_ecn_ce);
	PRINT_TCPSTAT(tcps_ecn_ect0);
	PRINT_TCPSTAT(tcps_ecn_ect1);
	PRINT_TCPSTAT(tcps_ecn_shs);
	PRINT_TCPSTAT(tcps_ecn_rcwnd);

	PRINT_TCPSTAT(tcps_sig_rcvgoodsig);
	PRINT_TCPSTAT(tcps_sig_rcvbadsig);
	PRINT_TCPSTAT(tcps_sig_err_buildsig);
	PRINT_TCPSTAT(tcps_sig_err_sigopt);
	PRINT_TCPSTAT(tcps_sig_err_nosigopt);

#undef PRINT_TCPSTAT

	printf("\n");
	printf("========================================================================\n");
}


static void
if_stats_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct interface_config *cfg = w->data;

	dump_ifstat(cfg->uinst, cfg->alias);
	printf("num_sockets=%llu max_accept_batch=%llu\n", (unsigned long long)cfg->num_sockets, (unsigned long long)cfg->max_accept_batch);
	if (cfg->do_tcpstats) {
		dump_tcpstat(cfg->uinst);
	}
}


void *interface_thread_start(void *arg)
{
	struct interface_config *cfg = arg;
	ev_timer if_stats_timer;

	uinet_initialize_thread();

	if (cfg->stats) {
		ev_init(&if_stats_timer, if_stats_timer_cb);
		ev_timer_set(&if_stats_timer, 1.0, 2.0);
		if_stats_timer.data = cfg;
		ev_timer_start(cfg->loop, &if_stats_timer);
	}

	ev_run(cfg->loop, 0);

	uinet_finalize_thread();

	return (NULL);
}


static void
usage(const char *progname)
{

	printf("Usage: %s [options]\n", progname);
#ifdef ENABLE_EXTRACT
	printf("    -c content_type      content type to extract from connections on current server\n");
	printf("    -e                   extract certain http responses\n");
#endif
	printf("    -h                   show usage\n");
	printf("    -i ifname            specify network interface\n");
	printf("    -l inaddr            listen address\n");
	printf("    -P                   put interface into Promiscuous INET mode\n");
	printf("    -p port              listen port [0, 65535]\n");
	printf("    -s                   periodically print stats for interface\n");
	printf("    -t iftype            interface type [netmap, pcap]\n");
	printf("    -v                   be verbose\n");
}


int main (int argc, char **argv)
{
	int ch;
	char *progname = argv[0];
#define MIN_INTERFACES 1
#define MAX_INTERFACES 64
	struct interface_config interfaces[MAX_INTERFACES];
#define MIN_SERVERS 1
#define MAX_SERVERS 64	
	struct server_config servers[MAX_SERVERS];
	int num_interfaces = 0;
	int num_servers = 0;
	int interface_server_count = 0;
	int verbose = 0;
	int stats = 0;
	int tcp_stats_assigned = 0;
	unsigned int i;
	int error;
	struct uinet_in_addr tmpinaddr;
	int ifnetmap_count = 0;
	int ifpcap_count = 0;
	struct content_type *contype;

	memset(interfaces, 0, sizeof(interfaces));
	memset(servers, 0, sizeof(servers));

	for (i = 0; i < MAX_INTERFACES; i++) {
		interfaces[i].type = UINET_IFTYPE_NETMAP;
	}

	for (i = 0; i < MAX_SERVERS; i++) {
		servers[i].listen_port = -1;
	}

	while ((ch = getopt(argc, argv, "c:ehi:l:Pp:st:v")) != -1) {
		switch (ch) {
		case 'c':
#ifdef ENABLE_EXTRACT
			if (0 == interface_server_count) {
				printf("No listen address specified\n");
				return (1);
			} else if (MAX_CONTENT_TYPES == servers[num_servers - 1].num_content_types) {
				printf("Maximum number of content types per server is %u\n", MAX_CONTENT_TYPES);
				return (1);
			} else {
				contype = find_content_type(optarg, known_content_types);
				if (NULL == contype) {
					printf("Unknown content type %s\n", optarg);
					return (1);
				}
				servers[num_servers - 1].extract = 1;
				servers[num_servers - 1].content_types[servers[num_servers - 1].num_content_types] = contype;
				servers[num_servers - 1].num_content_types++;
			}
#else
			printf("Extract mode not supported.\n");
			return(1);
#endif
			break;
		case 'e':
#ifdef ENABLE_EXTRACT
			if (0 == num_interfaces) {
				printf("No interface specified\n");
				return (1);
			} else {
				servers[num_servers - 1].extract = 1;
			}
#else
			printf("Extract mode not supported.\n");
			return(1);
#endif
			break;
		case 'h':
			usage(progname);
			return (0);
		case 'i':
			if (MAX_INTERFACES == num_interfaces) {
				printf("Maximum number of interfaces is %u\n", MAX_INTERFACES);
				return (1);
			} else {
				interfaces[num_interfaces].ifname = optarg;
				interfaces[num_interfaces].cdom = num_interfaces + 1;
				num_interfaces++;
				interface_server_count = 0;
			}
			break;
		case 'l':
			if (0 == num_interfaces) {
				printf("No interface specified\n");
				return (1);
			} else if (MAX_SERVERS == num_servers) {
				printf("Maximum number of servers is %u\n", MAX_SERVERS);
				return (1);
			} else {
				servers[num_servers].listen_addr = optarg;
				servers[num_servers].interface = &interfaces[num_interfaces - 1];
				num_servers++;
				interface_server_count++;
			}
			break;
		case 'P':
			if (0 == num_interfaces) {
				printf("No interface specified\n");
				return (1);
			} else {
				interfaces[num_interfaces - 1].promisc = 1;
			}
			break;
		case 'p':
			if (0 == interface_server_count) {
				printf("No listen address specified\n");
				return (1);
			} else {
				servers[num_servers - 1].listen_port = strtoul(optarg, NULL, 10);
			}
			break;
		case 's':
			if (0 == num_interfaces) {
				printf("No interface specified\n");
				return (1);
			} else {
				interfaces[num_interfaces - 1].stats = 1;
			}
			break;
		case 't':
			if (0 == num_interfaces) {
				printf("No interface specified\n");
				return (1);
			} else if (0 == strcmp(optarg, "netmap")) {
				interfaces[num_interfaces - 1].type = UINET_IFTYPE_NETMAP;
			} else if (0 == strcmp(optarg, "pcap")) {
				interfaces[num_interfaces - 1].type = UINET_IFTYPE_PCAP;
			} else {
				printf("Unknown interface type %s\n", optarg);
				return (1);
			}
			break;
		case 'v':
			verbose++;
			break;
		default:
			printf("Unknown option \"%c\"\n", ch);
		case '?':
			usage(progname);
			return (1);
		}
	}
	argc -= optind;
	argv += optind;

	if (num_interfaces < MIN_INTERFACES) {
		printf("Specify at least %u interface%s\n", MIN_INTERFACES, MIN_INTERFACES == 1 ? "" : "s");
		return (1);
	}

	if (num_servers < MIN_SERVERS) {
		printf("Specify at least %u listen address%s\n", MIN_SERVERS, MIN_SERVERS == 1 ? "" : "es");
		return (1);
	}

	for (i = 0; i < num_servers; i++) {
		if (-1 == servers[i].listen_port) {
			printf("No listen port specified for interface %s, listen address %s\n",
			       servers[i].interface->ifname, servers[i].listen_addr);
			return (1);
		}

		if (servers[i].listen_port < 0 || servers[i].listen_port > 65535) {
			printf("Listen port for interface %s, listen address %s is out of range [0, 65535]\n",
			       servers[i].interface->ifname, servers[i].listen_addr);
			return (1);
		}

		if (0 == servers[i].listen_port)
			servers[i].interface->promisc = 1;

		if (uinet_inet_pton(UINET_AF_INET, servers[i].listen_addr, &tmpinaddr) <= 0) {
			printf("%s is not a valid listen address\n", servers[i].listen_addr);
			return (1);
		}

		if (tmpinaddr.s_addr == UINET_INADDR_ANY) {
			servers[i].addrany = 1;
			servers[i].interface->promisc = 1;
		}
	}
	
	
	uinet_init(1, 128*1024, NULL);
	uinet_install_sighandlers();

	for (i = 0; i < num_interfaces; i++) {
		interfaces[i].uinst = uinet_instance_default();

		switch (interfaces[i].type) {
		case UINET_IFTYPE_NETMAP:
			interfaces[i].alias_prefix = "netmap";
			interfaces[i].instance = ifnetmap_count;
			ifnetmap_count++;
			break;
		case UINET_IFTYPE_PCAP:
			interfaces[i].alias_prefix = "pcap";
			interfaces[i].instance = ifpcap_count;
			ifpcap_count++;
			break;
		default:
			printf("Unknown interface type %d\n", interfaces[i].type);
			return (1);
			break;
		}

		if (interfaces[i].stats && !tcp_stats_assigned) {
			interfaces[i].do_tcpstats = 1;
			tcp_stats_assigned = 1;
		}

		snprintf(interfaces[i].alias, UINET_IF_NAMESIZE, "%s%d", interfaces[i].alias_prefix, interfaces[i].instance);

		if (verbose) {
			printf("Creating interface %s, Promiscuous INET %s, cdom=%u\n",
			       interfaces[i].alias, interfaces[i].promisc ? "enabled" : "disabled",
			       interfaces[i].promisc ? interfaces[i].cdom : 0);
		}

		error = uinet_ifcreate(interfaces[i].uinst, interfaces[i].type, interfaces[i].ifname, interfaces[i].alias,
				       interfaces[i].promisc ? interfaces[i].cdom : 0,
				       0, &interfaces[i].uif);
		if (0 != error) {
			printf("Failed to create interface %s (%d)\n", interfaces[i].alias, error);
		}

		interfaces[i].loop = ev_loop_new(EVFLAG_AUTO);
		if (NULL == interfaces[i].loop) {
			printf("Failed to create event loop interface %s\n", interfaces[i].alias);
			break;
		}

		ev_loop_attach_uinet_interface(interfaces[i].loop, interfaces[i].uif);
	}
	
		
	for (i = 0; i < num_servers; i++) {
		if (!servers[i].addrany) {
			if (verbose) {
				printf("Adding address %s to interface %s\n", servers[i].listen_addr, servers[i].interface->alias);
			}
			
			error = uinet_interface_add_alias(servers[i].interface->uinst, servers[i].interface->alias, servers[i].listen_addr, "", "");
			if (error) {
				printf("Adding alias %s to interface %s failed (%d)\n", servers[i].listen_addr, servers[i].interface->alias, error);
			}
		}
	}


	for (i = 0; i < num_servers; i++) {
		if (verbose) {
			printf("Creating passive server at %s:%d on interface %s\n",
			       servers[i].listen_addr, servers[i].listen_port,
			       servers[i].interface->alias);
		}

		servers[i].verbose = verbose;

		servers[i].passive = create_passive(servers[i].interface->loop, &servers[i]);
		if (NULL == servers[i].passive) {
			printf("Failed to create passive server at %s:%d on interface %s\n",
			       servers[i].listen_addr, servers[i].listen_port,
			       servers[i].interface->alias);
			break;
		}
	}


	for (i = 0; i < num_interfaces; i++) {
		if (verbose) {
			printf("Bringing up interface %s\n", interfaces[i].alias);
		}

		error = uinet_interface_up(interfaces[i].uinst, interfaces[i].alias, 1, interfaces[i].promisc);
		if (0 != error) {
			printf("Failed to bring up interface %s (%d)\n", interfaces[i].alias, error);
		}

		if (verbose)
			printf("Creating interface thread for interface %s\n", interfaces[i].alias);

		interfaces[i].thread_create_result = pthread_create(&interfaces[i].thread, NULL,
								    interface_thread_start, &interfaces[i]);
	}

	for (i = 0; i < num_interfaces; i++) {
		if (0 == interfaces[i].thread_create_result)
			pthread_join(interfaces[i].thread, NULL);
	}

	uinet_shutdown(0);

	return (0);
}
