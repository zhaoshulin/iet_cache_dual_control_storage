/*
 * cache_conn/cache_sender.c
 *
 * handlers for sending data or state(ack, wrote index)
 *
 * Copyright (C) 2014-2015 Bing Sun <b.y.sun.cn@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public Licens
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */


#include "cache_conn.h"

/**
 * cache_header_size  -  size of a packet header
 *
 * The header size is a multiple of 8, so any payload following the header is
 * word aligned on 64-bit architectures.  (The bitmap send and receive code
 * relies on this.)
 */
unsigned int cache_header_size(struct cache_connection *conn)
{
	return sizeof(struct p_header80);
}

static void *conn_prepare_command(struct cache_connection *conn, struct cache_socket *sock)
{ /*移动p指针到结构体那里去*/
	void *p;

	mutex_lock(&sock->mutex);
	if (!sock->socket){
		p = NULL;
		mutex_unlock(&sock->mutex);
	}else
		p = sock->sbuf + cache_header_size(conn);	

	return p;
}

static unsigned int prepare_header80(struct p_header80 *h, enum cache_packet cmd, int size, enum mesi from, enum mesi to)
{
	h->magic   = cpu_to_be16(CACHE_MAGIC);
	h->command = cpu_to_be16(cmd);
	h->length  = cpu_to_be32(size);
	if(from != NIL)
		h->from = from;
	if(to != NIL)
		h->to = to;//在此处把mesi存到了buffer里
	return sizeof(struct p_header80);
}

static unsigned int prepare_header(struct cache_connection *conn, 
							void *buffer, enum cache_packet cmd, int size, enum mesi from, enum mesi to)
{/*构造header，buffer指针指向它*/

		return prepare_header80(buffer, cmd, size, from, to);
}


/* called on sndtimeo
 * returns false if we should retry,
 * true if we think connection is dead
 */
static int we_should_drop_the_connection(struct cache_connection *connection, struct socket *sock)
{
	int drop_it;

	drop_it =  (!peer_is_good || !connection->ko_count); 

	if (drop_it)
		return true;

	drop_it = !--connection->ko_count;
	if (!drop_it) {
		cache_err("[%s/%d] sock_sendmsg time expired, ko = %u\n",
			 current->comm, current->pid, connection->ko_count);
	}

	return drop_it;
}

/*
 * you must have down()ed the appropriate [m]sock_mutex elsewhere!
 */
static int cache_send(struct cache_connection *connection, struct socket *sock,
	      void *buf, size_t size, unsigned msg_flags)
{
	struct kvec iov;
	struct msghdr msg;
	int rv, sent = 0;

	if (!sock)
		return -EBADR;

	/* THINK  if (signal_pending) return ... ? */

	iov.iov_base = buf;
	iov.iov_len  = size;

	msg.msg_name       = NULL;
	msg.msg_namelen    = 0;
	msg.msg_control    = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags      = msg_flags | MSG_NOSIGNAL;

	do {
		/* STRANGE
		 * tcp_sendmsg does _not_ use its size parameter at all ?
		 *
		 * -EAGAIN on timeout, -EINTR on signal.
		 */

		rv = kernel_sendmsg(sock, &msg, &iov, 1, size);
		if (rv == -EAGAIN) {
			if(we_should_drop_the_connection(connection, sock))
				break;
			else{
				cache_dbg("Send data fail, try again.\n");
				continue;
			}
		}
		if (rv == -EINTR) {
			flush_signals(current);
			rv = 0;
		}
		if (rv < 0)
			break;
		sent += rv;
		iov.iov_base += rv;
		iov.iov_len  -= rv;
	} while (sent < size);

	if (rv <= 0) {
		cache_err("%s_sendmsg returned %d\n",
			 sock == connection->state.socket ? "msock" : "sock", rv);
		return rv;
	}

	return sent;
}

/**
 * cache_send_all  -  Send an entire buffer
 *
 * Returns 0 upon success and a negative error value otherwise.
 */
static int cache_send_all(struct cache_connection *connection, struct socket *sock, void *buffer,
		  size_t size, unsigned msg_flags)
{
	int err;

	err = cache_send(connection, sock, buffer, size, msg_flags);
	if (err < 0)
		return err;
	if (err != size)
		return -EIO;
	return 0;
}

/**
*	@size: total cache data 
*/
static int __send_command(struct cache_connection *conn,
			  struct cache_socket *sock, enum cache_packet cmd,
			  int header_size, void *data,
			  int size, enum mesi from, enum mesi to)
{
	int msg_flags;
	int err;
	int total_size;

	/*
	 * Called with @data == NULL and the size of the data blocks in @size
	 * for commands that send data blocks.  For those commands, omit the
	 * MSG_MORE flag: this will increase the likelihood that data blocks
	 * which are page aligned on the sender will end up page aligned on the
	 * receiver.
	 */
	msg_flags = data ? MSG_MORE : 0;

//	header_size += prepare_header(conn, sock->sbuf, cmd,
//				      header_size + size, from, to);
	total_size = header_size + prepare_header(conn, sock->sbuf, cmd,
				      header_size + size, from, to);

	err = cache_send_all(conn, sock->socket, sock->sbuf, total_size,
			    msg_flags);
	
	if (data && !err)
		err = cache_send_all(conn, sock->socket, data, size, 0);
	return err;
}

static int conn_send_command(struct cache_connection *tconn, struct cache_socket *sock,
		      enum cache_packet cmd, int header_size,
		      void *data, int size)
{
	int err;

	err = __send_command(tconn, sock, cmd, header_size, data, size, NIL, NIL);
	mutex_unlock(&sock->mutex);
	return err;
}


int send_first_packet(struct cache_connection *connection, struct cache_socket *sock,
			     enum cache_packet cmd)
{
	if (!conn_prepare_command(connection, sock))
		return -EIO;
	return conn_send_command(connection, sock, cmd, 0, NULL, 0);
}

static int _cache_send_page(struct cache_connection*conn, struct page *page,
		    int offset, size_t size, unsigned msg_flags)
{
	struct socket *socket = conn->data.socket;
	mm_segment_t oldfs = get_fs();
	int len = size;
	int err = -EIO;

	msg_flags |= MSG_NOSIGNAL;

	set_fs(KERNEL_DS);
	do {
		int sent;

		sent = socket->ops->sendpage(socket, page, offset, len, msg_flags);
		if (sent <= 0) {
			if (sent == -EAGAIN) {
				if(we_should_drop_the_connection(conn, conn->data.socket))
					break;
				else{
					cache_dbg("Send data fail, try again.\n");
					continue;
				}

			}
			if (sent < 0)
				err = sent;
			break;
		}
		len -= sent;
		offset += sent;
	} while (len > 0);
	set_fs(oldfs);

	if (len == 0)
		err = 0;
	
	return err;
}

static int _cache_send_zc_pages(struct cache_connection *conn, struct page **pages, 
				int count, size_t size)
{
	int i;
	/* hint all but last page with MSG_MORE */
	for (i = 0; i < count; i++){
		int err, write;
		write = min_t(int, PAGE_SIZE, size);
		err = _cache_send_page(conn, pages[i],
					 0, write,
					 i == count - 1 ? 0 : MSG_MORE);
		if (err)
			return err;
		size -= write;
	}
	return 0;
}

int cache_send_dblock(struct cache_connection *connection, struct page **pages, 
				int count, u32 size, sector_t sector, struct cache_request ** req)
{
	struct cache_socket *sock;
	struct p_data *p;
	u32 seq_num;
	int err;

	sock = &connection->data;
	
	p = conn_prepare_command(connection, sock);
	if (!p)
		return -EIO;
	
	seq_num= atomic_inc_return(&connection->packet_seq);
	*req = cache_request_alloc(connection, seq_num);
	cache_request_enqueue(*req);
	
	p->sector = cpu_to_be64(sector);
	p->block_id = (u64)pages;
	p->seq_num = cpu_to_be32(seq_num);
	
	cache_dbg("begin to send cmd.\n");
	err = __send_command(connection, sock, P_DATA, sizeof(*p), NULL, size, NIL, NIL); /* size of total data written to device */
	
	cache_dbg("finish sending cmd, begin to send data.\n");
	if (!err) {
		err = _cache_send_zc_pages(connection, pages, count, size);
	}
	cache_dbg("finish sending data.\n");
	
	mutex_unlock(&sock->mutex);  /* locked by conn_prepare_command() */

	if(err)
		cache_request_dequeue(*req);

	return err;
}





// send one page!
int send_data_zsl(struct cache_connection*conn, pgoff_t page_index, struct page *page, sector_t sector,
		     size_t size, struct cache_request ** req, enum mesi from, enum mesi to, enum rwwb rw)
{
	int wrote;
	unsigned msg_flags;
	u32 seq_num;
	int err = -EIO;
	struct cache_socket *sock = &conn->data;
	struct p_data *p;

	//  1, send cmd	
	p = conn_prepare_command(conn, sock);
	if (!p)
		return -EIO;
	
	seq_num= atomic_inc_return(&conn->packet_seq);
	*req = cache_request_alloc(conn, seq_num);
	cache_request_enqueue(*req);
	p->seq_num = cpu_to_be32(seq_num);
	p->rw = rw;
	p->sector = cpu_to_be64(sector);
	p->from = from;
	p->to = to;
	p->page_index = page_index;
	
	cache_dbg("send_data: begin to send cmd, from = %d, to = %d, rw = %d, page_index = %ld...\n", from, to, rw, page_index);
	err = __send_command(conn, sock, P_DATA, sizeof(*p), NULL, size, from, to);
	mutex_unlock(&sock->mutex);  /* locked by conn_prepare_command() */ 
	cache_dbg("send_data: send cmd is finished. Now start to send data...\n");

	
	//2, send data_page
	if(!err){
		if(size == PAGE_SIZE){
			wrote = PAGE_SIZE;
			msg_flags = 0;
		}else if (size < PAGE_SIZE){
			wrote = size;
			msg_flags = 0;
		}
		err = _cache_send_page(conn, page, 0, wrote, 0);
		if(err)
			return err;
	}

	cache_alert("send page_index = %ld ok.\n", (sector>>3));
	return 0;
}

// send one_page_ack:
int send_data_ack_zsl(struct cache_connection *connection, pgoff_t page_index, u32 seq_num, sector_t sector, enum mesi from, enum mesi to)
{
		struct cache_socket *sock;
		struct p_data_ack *p;
		struct socket * socket;
		int err;
		
		sock = &connection->data;
		socket = sock->socket;
		
		p = conn_prepare_command(connection, sock);
		if (!p)
			return -EIO;
	
		p->seq_num = cpu_to_be32(seq_num);
		p->sector = cpu_to_be64(sector);
		p->from = from;
		p->to = to;
		p->page_index = page_index;
	
		cache_dbg("begin to send data_ack, trying from = %d, to = %d, page_index = %ld...\n", from, to, page_index);
		err = __send_command(connection, sock, P_DATA_ACK, sizeof(*p), NULL, 0, from, to);
	
		cache_dbg("finish sending data_ack.\n");
		
		mutex_unlock(&sock->mutex);  /* locked by conn_prepare_command() */ 
		
		return err;
}

// send one_page's state
int send_state_zsl(struct cache_connection *connection, sector_t sector,
	pgoff_t page_index, struct cache_request **req, enum mesi from, enum mesi to, enum rwwb rw)
{
		struct cache_socket *sock;
		struct p_state *p;
		struct socket * socket;
		int err;
		int size = sizeof(pgoff_t) * 1;
		u32 seq_num;
		char *what;
		void *buffer = &page_index;
		
		sock = &connection->state;
		socket = sock->socket;
		
		p = conn_prepare_command(connection, sock);
		if (!p)
			return -EIO;
		seq_num = atomic_inc_return(&connection->packet_seq);
	
		p->seq_num = cpu_to_be32(seq_num);
		p->sector = cpu_to_be64(sector);
		p->from = from;
		p->to = to;
		p->rw = rw;
		*req = cache_request_alloc(connection, seq_num);
		cache_request_enqueue(*req);
	
		cache_dbg("begin to send state..., trying page_index = %ld, from = %d, to = %d, rw = %d, seq = %u.\n", page_index, from, to, rw, p->seq_num);
		err = __send_command(connection, sock, P_STATE, sizeof(*p), NULL, size, from, to);
		cache_dbg("send cmd is finished. Now start to send page_index.\n");
		what = "__send_command";
		if (!err){
			what = "cache_send_all";
			err = cache_send_all(connection, socket, buffer, size, 0);
		}
		mutex_unlock(&sock->mutex);  /* locked by conn_prepare_command() */ 
	
		if(err){
			cache_alert("send_state: send state fail. err_type is %s\n", what);
			cache_request_dequeue(*req);
			return err;
		}
	
		cache_dbg("send_state: send page_index is finished now.\n");
		cache_alert("send_state: already send page_index = %ld ok\n", page_index);
		return err;
}



//zsl: send one_page's state_ack:
int send_state_ack_zsl(struct cache_connection *connection, pgoff_t index,  u32 seq_num, enum mesi from, enum mesi to)
{
		struct cache_socket *sock;
		struct p_state_ack *p;
		struct socket * socket;
		int err;
		
		sock = &connection->state;
		socket = sock->socket;

		p = conn_prepare_command(connection, sock);
		if (!p)
			return -EIO;
	
		p->seq_num = cpu_to_be32(seq_num);
		p->from = from;
		p->to = to;
		p->page_index = index;
	
		cache_dbg("begin to send state_ack.\n");
		cache_alert("trying from = %d, to = %d, seq = %u page_index = %ld\n", p->from, p->to, p->seq_num, p->page_index);
		err = __send_command(connection, sock, P_STATE_ACK, sizeof(*p), NULL, 0, from, to);
		cache_dbg("finish sending state_ack.\n");
		
		mutex_unlock(&sock->mutex);  /* locked by conn_prepare_command() */ 
		
		return err;
	
}


//zsl: 
int send_data_ack(struct cache_connection *connection,  u32 seq_num, enum mesi from, enum mesi to)
{
	struct cache_socket *sock;
	struct p_data_ack *p;
	struct socket * socket;
	int err;
	
	sock = &connection->data;
	socket = sock->socket;


	
	p = conn_prepare_command(connection, sock);
	if (!p)
		return -EIO;

	p->seq_num = cpu_to_be32(seq_num);

	cache_dbg("begin to send data_ack.\n");
	err = __send_command(connection, sock, P_DATA_ACK, sizeof(*p), NULL, 0, from, to);
	cache_dbg("finish sending data_ack.\n");
	
	mutex_unlock(&sock->mutex);  /* locked by conn_prepare_command() */	
	
	return err;

}

//zsl:
int send_state(struct cache_connection *connection, struct page **pages, int count, u32 size, sector_t sector, struct cache_request ** req, enum mesi from, enum mesi to, enum rwwb rw)
{
		struct cache_socket *sock;
		struct p_state *p;
		u32 seq_num;
		int err;
	
		sock = &connection->state;
		
		p = conn_prepare_command(connection, sock);
		if (!p)
			return -EIO;
		
		seq_num= atomic_inc_return(&connection->packet_seq);
		*req = cache_request_alloc(connection, seq_num);
		cache_request_enqueue(*req);

		p->seq_num = cpu_to_be32(seq_num);
		p->rw = (rw == CAUSED_BY_READ)? CAUSED_BY_READ : CAUSED_BY_WRITE ;
		
		cache_dbg("begin to send state.\n");
		err = __send_command(connection, sock, P_STATE, sizeof(*p), NULL, size, from, to); /* size of total data written to device */
		cache_dbg("finish sending state.\n");
		
		mutex_unlock(&sock->mutex);  /* locked by conn_prepare_command() */
	
		if(err)
			cache_request_dequeue(*req);
	
		return err;
}


//zsl:
int send_state_ack(struct cache_connection *connection,  u32 seq_num, enum mesi from, enum mesi to)
{
		struct cache_socket *sock;
		struct p_state_ack *p;
		struct socket * socket;
		int err;
		
		sock = &connection->state;
		socket = sock->socket;
	
	
		
		p = conn_prepare_command(connection, sock);
		if (!p)
			return -EIO;
	
		p->seq_num = cpu_to_be32(seq_num);
	
		cache_dbg("begin to send data_ack.\n");
		err = __send_command(connection, sock, P_DATA_ACK, sizeof(*p), NULL, 0, from, to);
		cache_dbg("finish sending data_ack.\n");
		
		mutex_unlock(&sock->mutex);  /* locked by conn_prepare_command() */ 
		
		return err;
	
}



int cache_send_wrote(struct cache_connection *connection, 
	pgoff_t *pages_index, int count, struct cache_request **req)
{
	struct cache_socket *sock;
	struct p_block_wrote *p;
	struct socket * socket;
	int err;
	int size = sizeof(pgoff_t) * count;
	u32 seq_num;
	
	sock = &connection->state;
	socket = sock->socket;

	cache_alert("try to send wrote...\n");
	
	p = conn_prepare_command(connection, sock);
	if (!p)
		return -EIO;
	seq_num = atomic_inc_return(&connection->packet_seq);

	p->seq_num = cpu_to_be32(seq_num);
	*req = cache_request_alloc(connection, seq_num);
	cache_request_enqueue(*req);

	cache_alert("begin to send wrote data.\n");
	err = __send_command(connection, sock, P_DATA_WRITTEN, sizeof(*p), NULL, size, S, E);
	if (!err)
		err = cache_send_all(connection, socket, pages_index, size, 0);

	mutex_unlock(&sock->mutex);  /* locked by conn_prepare_command() */	

	if(err){
		cache_err("send wrote data fail.\n");
		cache_request_dequeue(*req);
		return err;
	}

	cache_alert("finish sending wrote data.\n");
	return err;
}

int cache_send_data_ack(struct cache_connection *connection,  u32 seq_num, u64 sector)
{
	struct cache_socket *sock;
	struct p_data_ack *p;
	struct socket * socket;
	int err;
	
	sock = &connection->data;
	socket = sock->socket;
	
	p = conn_prepare_command(connection, sock);
	if (!p)
		return -EIO;

	p->seq_num = cpu_to_be32(seq_num);
	p->sector = cpu_to_be64(sector);

	cache_dbg("begin to send data ack.\n");
	err = __send_command(connection, sock, P_DATA_ACK, sizeof(*p), NULL, 0, NIL, NIL);

	cache_dbg("finish sending data ack.\n");
	
	mutex_unlock(&sock->mutex);  /* locked by conn_prepare_command() */	
	
	return err;
}

int cache_send_wrote_ack(struct cache_connection *connection,  u32 seq_num)
{
	struct cache_socket *sock;
	struct p_wrote_ack *p;
	struct socket * socket;
	int err;
	
	sock = &connection->state;
	socket = sock->socket;
	
	p = conn_prepare_command(connection, sock);
	if (!p)
		return -EIO;

	p->seq_num = cpu_to_be32(seq_num);

	cache_dbg("begin to send wrote ack.\n");
	err = __send_command(connection, sock, P_WRITTEN_ACK, sizeof(*p), NULL, 0, WAITING_ACK, S);

	cache_dbg("finish sending wrote ack.\n");
	
	mutex_unlock(&sock->mutex);  /* locked by conn_prepare_command() */	
	
	return err;
}

