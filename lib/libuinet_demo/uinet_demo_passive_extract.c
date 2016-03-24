/*
 * Copyright (c) 2013-2015 Patrick Kelsey. All rights reserved.
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
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include <netinet/in.h>

#include "http_parser.h"
#include "uinet_demo_passive_extract.h"
#include "uinet_demo_internal.h"


static void passive_extract_print_usage(void);
static int passive_extract_init_cfg(struct uinet_demo_config *cfg);
static int passive_extract_process_args(struct uinet_demo_config *cfg, int argc, char **argv);
static void passive_extract_print_cfg(struct uinet_demo_config *cfg);
static int passive_extract_start(struct uinet_demo_config *cfg, uinet_instance_t uinst,
			 struct ev_loop *loop);

struct uinet_demo_info passive_extract_info = {
	.which = UINET_DEMO_PASSIVE_EXTRACT,
	.name = "passive extract server",
	.cfg_size = sizeof(struct uinet_demo_passive_extract),
	.print_usage = passive_extract_print_usage,
	.init_cfg = passive_extract_init_cfg,
	.process_args = passive_extract_process_args,
	.print_cfg = passive_extract_print_cfg,
	.start = passive_extract_start
};


enum passive_extract_option_id {
	PASSIVE_EXTRACT_OPT_CONTENT_TYPE = 1000,
	PASSIVE_EXTRACT_OPT_LISTEN
};

static const struct option passive_extract_long_options[] = {
	UINET_DEMO_BASE_LONG_OPTS,
	{ "content-type", required_argument,	NULL, PASSIVE_EXTRACT_OPT_CONTENT_TYPE },
	{ "listen",	required_argument,	NULL, PASSIVE_EXTRACT_OPT_LISTEN },
	{ 0, 0, 0, 0 }
};


struct content_type {
	const char *type;
	const char *file_ext;
};

struct value_buffer {
#define MAX_VALUE_LENGTH 127
	char data[MAX_VALUE_LENGTH + 1];
	int index;
};

struct passive_connection {
	char label[64];
	ev_uinet watcher;
	ev_uinet connected_watcher;
	struct uinet_demo_passive_extract *server;
	uint64_t bytes_read;
	int verbose;
	struct passive_connection *peer;

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
};


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


static inline int imin(int a, int b) { return (a < b ? a : b); }


static void
destroy_conn(struct passive_connection *conn)
{
	ev_uinet *w  = &conn->watcher;

	ev_uinet_stop(conn->server->cfg.loop, &conn->connected_watcher);
	ev_uinet_stop(conn->server->cfg.loop, w);
	ev_uinet_detach(w->ctx);
	uinet_soclose(ev_uinet_so(w->ctx));
	conn->server->num_sockets--;
	if (conn->buffer)
		free(conn->buffer);
	if (conn->parser)
		free(conn->parser);
	if (conn->parser_settings)
		free(conn->parser_settings);
	free(conn);
}


static void
passive_extract_parse_buffer(struct passive_connection *conn)
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
	struct passive_connection *conn = w->data;
	struct uinet_demo_passive_extract *passive = conn->server;
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
		if (conn->verbose) {
			printf("%s: %s: can't read, closing\n",
			       passive->cfg.name, conn->label);
			printf("%s: %s: closing because passive peer is closing\n",
			       conn->peer->server->cfg.name, conn->peer->label);
		}
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
			printf("%s: %s: read error (%d), closing\n",
			       passive->cfg.name, conn->label, error);
			goto err;
		}

		if (flags & UINET_MSG_HOLE_BREAK) {
			printf("%s: %s: hole in data, closing connections\n",
			       passive->cfg.name, conn->label);
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
						printf("%s: %s: completed parsing request or response\n",
						       passive->cfg.name, conn->label);
					http_parser_pause(conn->peer->parser, 0);
					passive_extract_parse_buffer(conn->peer);
					if (HTTP_PARSER_ERRNO(conn->peer->parser) == HPE_OK) {
						if (conn->verbose > 1)
							printf("%s: %s: peer needs more data\n",
							       passive->cfg.name, conn->label);
						/* Peer parser needs more data */
						ev_uinet_stop(loop, &conn->watcher);
						ev_uinet_start(loop, &conn->peer->watcher);
						break;
					} else if (HTTP_PARSER_ERRNO(conn->peer->parser) != HPE_PAUSED) {
						printf("%s: %s: Peer parse failure %s, closing connections\n",
						       passive->cfg.name,
						       conn->label,
						       http_errno_name(HTTP_PARSER_ERRNO(conn->peer->parser)));
						goto err;
					} else {
						if (conn->verbose > 1)
							printf("%s: %s: peer completed parsing request or response\n",
							       passive->cfg.name, conn->label);
						/*
						 * The other parser has paused, so it's time for us to continue
						 * parsing/receiving.
						 */
						http_parser_pause(conn->parser, 0);
					}
				} else {
					printf("%s: %s: Parse failure %s, closing connections\n",
					       passive->cfg.name,
					       conn->label,
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


static void
passive_extract_connected_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct passive_connection *conn = w->data;
	struct uinet_demo_passive_extract *passive = conn->server;
	int error;

	if (passive->cfg.verbose)
		printf("%s: %s: connection established\n", passive->cfg.name, conn->label);

	if ((passive->cfg.copy_mode & UINET_IP_COPY_MODE_MAYBE) &&
	    ((uinet_sogetserialno(w->so) % passive->cfg.copy_every) == 0)){
		if ((error =
		     uinet_sosetcopymode(w->so, UINET_IP_COPY_MODE_RX|UINET_IP_COPY_MODE_ON,
					 passive->cfg.copy_limit, passive->cfg.copy_uif)))
			printf("%s: Failed to set copy mode (%d)\n",
			       passive->cfg.name, error);
	}

	ev_uinet_stop(loop, w);
}


static int
on_http_req_message_begin(http_parser *parser)
{
	struct passive_connection *conn = parser->data;

	conn->ishead = 0;

	return (0);
}


static int
on_http_req_message_complete(http_parser *parser)
{
	struct passive_connection *conn = parser->data;

	if (conn->verbose)
		printf("%s: %s: request type: %s\n",
		       conn->server->cfg.name, conn->label, http_method_str(parser->method));

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
	struct passive_connection *conn = parser->data;

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
	struct passive_connection *conn = parser->data;

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
	struct passive_connection *conn = parser->data;

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
	struct content_type **curtype;

	curtype = list;
	while (*curtype) {
		if (strcasecmp(str, (*curtype)->type) == 0)
			return *curtype;
		curtype++;
	}
	curtype = list;
	while (*curtype) {
		if (strcasecmp(str, &((*curtype)->file_ext[1])) == 0)
			return *curtype;
		curtype++;
	}
	return (NULL);
}


static int
on_http_resp_headers_complete(http_parser *parser)
{
	struct passive_connection *conn = parser->data;
	struct content_type *type;
	char filename[80];
	int offset;
	int thereisnobody;

	/* Ensure the last value stored is nul-terminated */
	if (conn->value)
		conn->value->data[conn->value->index] = '\0';

	if (conn->verbose) {
		    printf("%s: %s: content type: %s\n",
			   conn->server->cfg.name, conn->label,
			   conn->content_type.index ? conn->content_type.data : "<unknown>");
		    printf("%s: %s: content encoding: %s\n",
			   conn->server->cfg.name, conn->label,
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
	struct passive_connection *conn = parser->data;
	uint8_t inflate_buffer[1024];
	int error;

	if (conn->verbose > 2)
		printf("%s: %s: received %zu body bytes\n",
		       conn->server->cfg.name, conn->label, length);

	if (conn->extract_body) {
		if (conn->inflate) {
			conn->zstrm.avail_in = length;
			conn->zstrm.next_in = (unsigned char *)at;

			do {
				conn->zstrm.avail_out = sizeof(inflate_buffer);
				conn->zstrm.next_out = inflate_buffer;

				error = inflate(&conn->zstrm, Z_NO_FLUSH);
				if (error != Z_OK && error != Z_STREAM_END) {
					printf("%s: %s: error while inflating %d, skipping rest of body\n",
					       conn->server->cfg.name, conn->label, error);
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
	struct passive_connection *conn = parser->data;

	if (conn->verbose > 1)
		printf("%s: %s: response complete\n",
		       conn->server->cfg.name, conn->label);

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
parser_init(struct passive_connection *conn, enum http_parser_type type)
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


static struct passive_connection *
create_conn(struct uinet_demo_passive_extract *passive, struct uinet_socket *so, int server)
{
	struct passive_connection *conn = NULL;
	struct ev_uinet_ctx *soctx = NULL;
	struct uinet_sockaddr_in *sin1, *sin2;
	char buf1[32], buf2[32];
	time_t now_timet;
	struct tm now;
#define EXTRACT_BUFFER_SIZE 1024

	conn = calloc(1, sizeof(*conn));
	if (NULL == conn) {
		printf("%s: Failed to alloc connection context for new connection\n",
			passive->cfg.name);
		goto fail;
	}

	soctx = ev_uinet_attach(so);
	if (NULL == soctx) {
		printf("%s: Failed to alloc libev context for new connection socket\n",
			passive->cfg.name);
		goto fail;
	}

	uinet_sogetsockaddr(so, (struct uinet_sockaddr **)&sin1);
	uinet_sogetpeeraddr(so, (struct uinet_sockaddr **)&sin2);
	snprintf(conn->label, sizeof(conn->label), "%s (%s:%u <- %s:%u)",
		 server ? "SERVER" : "CLIENT",
		 uinet_inet_ntoa(sin1->sin_addr, buf1, sizeof(buf1)), ntohs(sin1->sin_port),
		 uinet_inet_ntoa(sin2->sin_addr, buf2, sizeof(buf2)), ntohs(sin2->sin_port));

	if (!server) {
		time(&now_timet);
		localtime_r(&now_timet, &now);
		snprintf(conn->filename_prefix, sizeof(conn->filename_prefix),
			 "extract-%04d%02d%02d-%02d%02d.%02d-%s.%u-%s.%u",
			 now.tm_year + 1900, now.tm_mon + 1, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec,
			 uinet_inet_ntoa(sin1->sin_addr, buf1, sizeof(buf1)), ntohs(sin1->sin_port),
			 uinet_inet_ntoa(sin2->sin_addr, buf2, sizeof(buf2)), ntohs(sin2->sin_port));
	}

	uinet_free_sockaddr((struct uinet_sockaddr *)sin1);
	uinet_free_sockaddr((struct uinet_sockaddr *)sin2);

	conn->verbose = passive->cfg.verbose;
	conn->server = passive;

	if (0 != parser_init(conn, server ? HTTP_REQUEST : HTTP_RESPONSE))
		goto fail;
	conn->buffer_size = EXTRACT_BUFFER_SIZE;
	conn->buffer = malloc(conn->buffer_size);
	if (NULL == conn->buffer)
		goto fail;
	ev_init(&conn->watcher, passive_extract_cb);
	ev_uinet_set(&conn->watcher, soctx, EV_READ);
	conn->watcher.data = conn;

	ev_init(&conn->connected_watcher, passive_extract_connected_cb);
	ev_uinet_set(&conn->connected_watcher, soctx, EV_WRITE);
	conn->connected_watcher.data = conn;

	return (conn);

fail:
	if (conn->buffer) free(conn->buffer);
	if (conn->parser) free(conn->parser);
	if (conn->parser_settings) free(conn->parser_settings);
	if (conn) free(conn);
	if (soctx) ev_uinet_detach(soctx);

	return (NULL);
}


static void
passive_extract_accept_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct uinet_demo_passive_extract *passive = w->data;
	struct uinet_socket *newso = NULL;
	struct uinet_socket *newpeerso = NULL;
	struct passive_connection *conn = NULL;
	struct passive_connection *peerconn = NULL;
	int error;
	unsigned int batch_limit = 32;
	unsigned int processed = 0;

	while ((processed < batch_limit) &&
	       (UINET_EWOULDBLOCK != (error = uinet_soaccept(w->so, NULL, &newso)))) {
		processed++;

		if (0 == error) {
			newpeerso = NULL;
			conn = NULL;
			peerconn = NULL;

			if (passive->cfg.verbose)
				printf("%s: Accept succeeded\n", passive->cfg.name);

			conn = create_conn(passive, newso, 1);
			if (NULL == conn) {
				printf("%s: Failed to alloc new connection context\n",
				       passive->cfg.name);
				goto fail;
			}

			newpeerso = uinet_sogetpassivepeer(newso);
			peerconn = create_conn(passive, newpeerso, 0);
			if (NULL == peerconn) {
				printf("%s: Failed to alloc new peer connection context\n",
				       passive->cfg.name);
				goto fail;
			}

			conn->peer = peerconn;
			peerconn->peer = conn;
			
			ev_uinet_start(loop, &conn->watcher);

			if (conn->verbose || (passive->cfg.copy_mode & UINET_IP_COPY_MODE_MAYBE))
				ev_uinet_start(loop, &conn->connected_watcher);

			if (peerconn->verbose || (passive->cfg.copy_mode & UINET_IP_COPY_MODE_MAYBE))
				ev_uinet_start(loop, &peerconn->connected_watcher);

			passive->num_sockets += 2;

			continue;
		fail:
			if (conn) destroy_conn(conn);
			if (newso) uinet_soclose(newso);
			if (newpeerso) uinet_soclose(newpeerso);
		}
	}

	if (processed > passive->max_accept_batch)
		passive->max_accept_batch = processed;
}


static void
passive_extract_print_usage(void)
{
	struct content_type **curtype;

	printf("  --content-type <type>   Long or short name of content type to extract (may be used multiple times)\n");
	printf("                          Valid content types (short name followed by long name):\n");
	curtype = known_content_types;
	while (*curtype) {
		printf("                            %-6s %s\n", &((*curtype)->file_ext[1]), (*curtype)->type);
		curtype++;
	}
	printf("  --listen <ip:port>      Specify the listen address and port (default is 0.0.0.0:0 - promiscuous listen on all ip:port pairs)\n");
}


static int
passive_extract_init_cfg(struct uinet_demo_config *cfg)
{
	struct uinet_demo_passive_extract *passive = (struct uinet_demo_passive_extract *)cfg;

	snprintf(passive->listen_addr, sizeof(passive->listen_addr), "%s", "0.0.0.0");
	passive->promisc = 1;

	return (0);
}


static int
passive_extract_process_args(struct uinet_demo_config *cfg, int argc, char **argv)
{
	struct uinet_demo_passive_extract *passive = (struct uinet_demo_passive_extract *)cfg;
	int opt;
	unsigned int num_content_types = 0;

	while ((opt = getopt_long(argc, argv, ":" UINET_DEMO_BASE_OPT_STRING,
				 passive_extract_long_options, NULL)) != -1) {
		switch (opt) {
		case PASSIVE_EXTRACT_OPT_CONTENT_TYPE:
		{
			struct content_type *contype;
			contype = find_content_type(optarg, known_content_types);
			if (NULL == contype) {
				printf("%s: Unknown content type %s\n", passive->cfg.name, optarg);
				return (1);
			}
			passive->content_types[num_content_types++] = contype;
			break;
		}
		case PASSIVE_EXTRACT_OPT_LISTEN:
			if (0 != uinet_demo_break_ipaddr_port_string(optarg, passive->listen_addr,
								     sizeof(passive->listen_addr),
								     &passive->listen_port)) {
				printf("%s: Invalid listen address and port specification %s\n",
				       passive->cfg.name, optarg);
				return (1);
			}
			break;
		case ':':
		case '?':
			return (opt);
		default:
			if (uinet_demo_base_process_arg(cfg, opt, optarg))
				return (opt);
			break;
		}
	}

	return (opt);
}


static void
passive_extract_print_cfg(struct uinet_demo_config *cfg)
{
	struct uinet_demo_passive_extract *passive = (struct uinet_demo_passive_extract *)cfg;
	struct content_type **curtype;
	unsigned int num_types;

	printf("listen=%s:%u content-types=", passive->listen_addr, passive->listen_port);

	num_types = 0;
	curtype = passive->content_types;
	while(*curtype) {
		printf("%s%s", num_types > 0 ? "," : "", (*curtype)->type);		
		curtype++;
		num_types++;
	}
	if (num_types == 0)
		printf("<none>");
}


static int
passive_extract_start(struct uinet_demo_config *cfg, uinet_instance_t uinst, struct ev_loop *loop)
{
	struct uinet_demo_passive_extract *passive = (struct uinet_demo_passive_extract *)cfg;
	struct uinet_socket *listen_socket = NULL;
	struct ev_uinet_ctx *soctx = NULL;
	struct uinet_in_addr addr;
	int optlen, optval;
	int error;
	struct uinet_sockaddr_in sin;

	if (uinet_inet_pton(UINET_AF_INET, passive->listen_addr, &addr) <= 0) {
		printf("%s: Malformed address %s\n", passive->cfg.name, passive->listen_addr);
		error = UINET_EINVAL;
		goto fail;
	}

	error = uinet_socreate(passive->cfg.uinst, UINET_PF_INET, &listen_socket, UINET_SOCK_STREAM, 0);
	if (0 != error) {
		printf("%s: Listen socket creation failed (%d)\n", passive->cfg.name, error);
		goto fail;
	}

	soctx = ev_uinet_attach(listen_socket);
	if (NULL == soctx) {
		printf("%s: Failed to alloc libev socket context\n", passive->cfg.name);
		error = UINET_ENOMEM;
		goto fail;
	}
	
	if ((error = uinet_make_socket_passive(listen_socket))) {
		printf("%s: Failed to make listen socket passive (%d)\n", passive->cfg.name, error);
		goto fail;
	}

	if (passive->promisc) {
		if ((error = uinet_make_socket_promiscuous(listen_socket, NULL))) {
			printf("%s: Failed to make listen socket promiscuous (%d)\n", passive->cfg.name, error);
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
	uinet_sosetnonblocking(listen_socket, 1);

	/* Wait 5 seconds for connections to complete */
	optlen = sizeof(optval);
	optval = 5;
	if ((error = uinet_sosetsockopt(listen_socket, UINET_IPPROTO_TCP, UINET_TCP_KEEPINIT, &optval, optlen))) {
		printf("%s: Failed to set TCP_KEEPINIT (%d)\n", passive->cfg.name, error);
		goto fail;
	}

	/* Begin counting down to close after 10 seconds of idle */
	optlen = sizeof(optval);
	optval = 10;
	if ((error = uinet_sosetsockopt(listen_socket, UINET_IPPROTO_TCP, UINET_TCP_KEEPIDLE, &optval, optlen))) {
		printf("%s: Failed to set TCP_KEEPIDLE (%d)\n", passive->cfg.name, error);
		goto fail;
	}

	/* Count down to close once per second */
	optlen = sizeof(optval);
	optval = 1;
	if ((error = uinet_sosetsockopt(listen_socket, UINET_IPPROTO_TCP, UINET_TCP_KEEPINTVL, &optval, optlen))) {
		printf("%s: Failed to set TCP_KEEPINTVL (%d)\n", passive->cfg.name, error);
		goto fail;
	}

	/* Close after idle for 3 counts */
	optlen = sizeof(optval);
	optval = 3;
	if ((error = uinet_sosetsockopt(listen_socket, UINET_IPPROTO_TCP, UINET_TCP_KEEPCNT, &optval, optlen))) {
		printf("%s: Failed to set TCP_KEEPCNT (%d)\n", passive->cfg.name, error);
		goto fail;
	}

	/* Wait 100 milliseconds for missing TCP segments */
	optlen = sizeof(optval);
	optval = 100;
	if ((error = uinet_sosetsockopt(listen_socket, UINET_IPPROTO_TCP, UINET_TCP_REASSDL, &optval, optlen))) {
		printf("%s: Failed to set TCP_REASSDL (%d)\n", passive->cfg.name, error);
		goto fail;
	}


	passive->listen_socket = listen_socket;

	memset(&sin, 0, sizeof(struct uinet_sockaddr_in));
	sin.sin_len = sizeof(struct uinet_sockaddr_in);
	sin.sin_family = UINET_AF_INET;
	sin.sin_addr = addr;
	sin.sin_port = htons(passive->listen_port);
	error = uinet_sobind(listen_socket, (struct uinet_sockaddr *)&sin);
	if (0 != error) {
		printf("%s: Bind to %s:%u failed\n", passive->cfg.name,
		       passive->listen_addr, passive->listen_port);
		goto fail;
	}
	
	error = uinet_solisten(passive->listen_socket, -1);
	if (0 != error) {
		printf("%s: Listen on %s:%u failed\n", passive->cfg.name,
		       passive->listen_addr, passive->listen_port);
		goto fail;
	}

	if (passive->cfg.verbose)
		printf("%s: Listening on %s:%u\n", passive->cfg.name,
		       passive->listen_addr, passive->listen_port);

	ev_init(&passive->listen_watcher, passive_extract_accept_cb);
	ev_uinet_set(&passive->listen_watcher, soctx, EV_READ);
	passive->listen_watcher.data = passive;
	ev_uinet_start(loop, &passive->listen_watcher);

	return (0);

fail:
	if (soctx) ev_uinet_detach(soctx);
	if (listen_socket) uinet_soclose(listen_socket);

	return (error);
}
