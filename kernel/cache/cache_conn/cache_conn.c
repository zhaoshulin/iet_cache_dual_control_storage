/*
 * cache_conn/cache_conn.c
 *
 * connection establishment between peers
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
#include "cache_receiver.h"
#include "../cache_config.h"

struct m_list_tag m_list;
struct e_list_tag e_list;
struct s_list_tag s_list;
struct i_list_tag i_list;
struct w_list_tag w_list;

static unsigned int inet_addr(const char* ip)
{
	int a, b, c, d;
	char addr[4];
	sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d);
	addr[0] = a;
	addr[1] = b;
	addr[2] = c;
	addr[3] = d;
	return *(unsigned int *)addr;
}

static char *inet_ntoa(struct in_addr *in)
{
	char* str_ip = NULL;
	u_int32_t int_ip = 0;	
	str_ip = kmalloc(16 * sizeof(char), GFP_KERNEL);
	if (!str_ip)
		return NULL;
	else
		memset(str_ip, 0, 16);
	int_ip = in->s_addr;
	sprintf(str_ip, "%d.%d.%d.%d",  (int_ip) & 0xFF,
		(int_ip >> 8) & 0xFF, (int_ip >> 16) & 0xFF,
		(int_ip >> 24) & 0xFF);	
	return str_ip;
}

static int sock_close(struct socket *sk)
{
	int ret;

	ret = sk->ops->release(sk);

	if (sk)
		sock_release(sk);

	return ret;
}

static int cache_alloc_socket(struct cache_socket *socket)
{
	socket->rbuf = (void *) __get_free_page(GFP_KERNEL);
	if (!socket->rbuf)
		return -ENOMEM;
	socket->sbuf = (void *) __get_free_page(GFP_KERNEL);
	if (!socket->sbuf)
		return -ENOMEM;
	return 0;
}

static void cache_free_socket(struct cache_socket *socket)
{
	free_page((unsigned long) socket->sbuf);
	free_page((unsigned long) socket->rbuf);
}

void cache_free_sock(struct cache_socket *cache_socket)
{
	if(!cache_socket)
		return;
	if (cache_socket->socket) {
		mutex_lock(&cache_socket->mutex);
		if (cache_socket->socket) {
			kernel_sock_shutdown(cache_socket->socket, SHUT_RDWR);
			sock_close(cache_socket->socket);
			cache_socket->socket = NULL;			
		}
		mutex_unlock(&cache_socket->mutex);
	}
}

static void cache_init_workqueue(struct cache_work_queue* wq)
{
	spin_lock_init(&wq->q_lock);
	INIT_LIST_HEAD(&wq->q);
	init_waitqueue_head(&wq->q_wait);
}

static void cache_thread_init(struct cache_thread *thi,
			     int (*func) (struct cache_thread *), const char *name)
{
	spin_lock_init(&thi->t_lock);
	thi->task    = NULL;
	thi->t_state = NONE;
	thi->function = func;
	thi->connection = NULL;
	thi->name = name;
}

static int cache_thread_setup(void *arg)
{
	struct cache_thread *thi = (struct cache_thread *) arg;
	unsigned long flags;
	int retval;

restart:
	retval = thi->function(thi);

	spin_lock_irqsave(&thi->t_lock, flags);

	if (thi->t_state == RESTARTING) {
		cache_info("Restarting %s thread\n", thi->name);
		thi->t_state = RUNNING;
		spin_unlock_irqrestore(&thi->t_lock, flags);
		goto restart;
	}

	thi->task = NULL;
	thi->t_state = NONE;
	complete(&thi->stop);
	
	spin_unlock_irqrestore(&thi->t_lock, flags);
	
	//module_put(THIS_MODULE);

	return retval;
}

int cache_thread_start(struct cache_thread *thi)
{
	struct task_struct *nt;
	unsigned long flags;

	/* is used from state engine doing cache_thread_stop_nowait,
	 * while holding the req lock irqsave */
	spin_lock_irqsave(&thi->t_lock, flags);

	switch (thi->t_state) {
	case NONE:
		cache_info("Starting %s thread\n", thi->name);

		/* Get ref on module for thread - this is released when thread exits 
		if (!try_module_get(THIS_MODULE)) {
			cache_err("Failed to get module reference in cache_thread_start\n");
			spin_unlock_irqrestore(&thi->t_lock, flags);
			return false;
		}
		

		if (thi->connection)
			kref_get(&thi->connection->kref);
		
		*/
		init_completion(&thi->start);
		init_completion(&thi->stop);
		thi->t_state = RUNNING;
		spin_unlock_irqrestore(&thi->t_lock, flags);
		flush_signals(current);  //otherw. may get -ERESTARTNOINTR

		nt = kthread_create(cache_thread_setup, (void *) thi,
				    "cache_%s", thi->name);

		if (IS_ERR(nt)) {
			cache_err("Couldn't start thread\n");
/*
			if (thi->connection)
				kref_put(&thi->connection->kref, cache_destroy_connection);

			module_put(THIS_MODULE);
*/
			return false;
		}
		spin_lock_irqsave(&thi->t_lock, flags);
		thi->task = nt;
		thi->t_state = RUNNING;
		spin_unlock_irqrestore(&thi->t_lock, flags);
		wake_up_process(nt);
		break;
	case EXITING:
		thi->t_state = RESTARTING;
		cache_info("Restarting %s thread ([%d])\n", thi->name, current->pid);
		/* fall through */
	case RUNNING:
	case RESTARTING:
	default:
		spin_unlock_irqrestore(&thi->t_lock, flags);
		break;
	}

	return true;
}

void _cache_thread_stop(struct cache_thread *thi, int restart, int wait)
{
	unsigned long flags;

	enum cache_thread_state ns = restart ? RESTARTING : EXITING;
	cache_dbg("begin to kill thread %s\n", thi->name);

	/* may be called from state engine, holding the req lock irqsave */
	spin_lock_irqsave(&thi->t_lock, flags);

	if (thi->t_state == NONE) {
		spin_unlock_irqrestore(&thi->t_lock, flags);
		if (restart)
			cache_thread_start(thi);
		return;
	}

	if (thi->t_state != ns) {
		if (thi->task == NULL) {
			spin_unlock_irqrestore(&thi->t_lock, flags);
			return;
		}

		thi->t_state = ns;
		smp_mb();
		init_completion(&thi->stop);
	}
	
	spin_unlock_irqrestore(&thi->t_lock, flags);

	if (wait)
		wait_for_completion(&thi->stop);
	cache_info("Thread %s exit.\n", thi->name);
}

/**
 * cache_socket_okay() - Free the socket if its connection is not okay
 * @sock:	pointer to the pointer to the socket.
 */
static int cache_socket_okay(struct socket **sock)
{
	int rr;
	char tb[4];

	if (!*sock)
		return false;

	rr = cache_recv_short(*sock, tb, 4, MSG_DONTWAIT | MSG_PEEK);

	if (rr > 0 || rr == -EAGAIN) {
		return true;
	} else {
		sock_release(*sock);
		*sock = NULL;
		return false;
	}
}

static struct socket *cache_wait_for_connect(struct cache_connection *connection, struct accept_wait_data *ad)
{
	int err = 0;
	struct socket *s_estab = NULL;

	cache_ignore("Server waits for accept.\n");
	err = kernel_accept(ad->s_data_listen, &s_estab, 0);
	if (err < 0) {
		if (err != -EAGAIN && err != -EINTR && err != -ERESTARTSYS) {
			cache_err("accept failed, err = %d\n", err);
		}

	}

	cache_ignore("Server finish accept.\n");
	return s_estab;
}



static struct socket *cache_wait_for_data_connect(struct cache_connection *connection, \
	struct accept_wait_data *ad)
{
	int err = 0;
	struct socket *s_estab = NULL;

	cache_dbg("Server waits for data_accept.\n");
	err = kernel_accept(ad->s_data_listen, &s_estab, 0);
	if (err < 0) {
		if (err != -EAGAIN && err != -EINTR && err != -ERESTARTSYS) {
			cache_err("accept failed, err = %d\n", err);
		}

	}

	cache_dbg("Server finish data_accept.\n");
	return s_estab;
}




static struct socket *cache_wait_for_state_connect(struct cache_connection *connection, struct accept_wait_data *ad)
{
	int err = 0;
	struct socket *s_estab = NULL;

	cache_dbg("Server waits for state_accept.\n");
	err = kernel_accept(ad->s_state_listen, &s_estab, 0);
	if (err < 0) {
		if (err != -EAGAIN && err != -EINTR && err != -ERESTARTSYS) {
			cache_err("accept failed, err = %d\n", err);
		}

	}

	cache_dbg("Server finish state_accept.\n");
	return s_estab;
}


static struct socket *cache_try_connect(struct cache_connection *connection)
{
	const char *what;
	struct socket *sock;
	struct sockaddr_in6 src_in6;
	struct sockaddr_in6 peer_in6;

	int err, peer_addr_len, my_addr_len;
	int sndbuf_size, rcvbuf_size, connect_int = 10;


	my_addr_len = min_t(int, connection->my_addr_len, sizeof(src_in6));
	memcpy(&src_in6, &connection->my_addr, my_addr_len);

	if (((struct sockaddr *)&connection->my_addr)->sa_family == AF_INET6)
		src_in6.sin6_port = 0;
	else
		((struct sockaddr_in *)&src_in6)->sin_port = 0; /* AF_INET & AF_SCI */

	peer_addr_len = min_t(int, connection->peer_addr_len, sizeof(src_in6));
	memcpy(&peer_in6, &connection->peer_addr, peer_addr_len);

	what = "sock_create_kern";
	err = sock_create_kern(((struct sockaddr *)&src_in6)->sa_family,
			       SOCK_STREAM, IPPROTO_TCP, &sock);
	if (err < 0) {
		sock = NULL;
		goto out;
	}

	sock->sk->sk_rcvtimeo =
	sock->sk->sk_sndtimeo = connect_int * HZ;

	what = "bind before connect";
	err = sock->ops->bind(sock, (struct sockaddr *) &src_in6, my_addr_len);
	if (err < 0)
		goto out;

	what = "connect";
	err = sock->ops->connect(sock, (struct sockaddr *) &peer_in6, peer_addr_len, 0);

out:
	if (err < 0) {		
		cache_dbg("cache_try_connect: %s failed, err = %d\n", what, err);
		if (sock) {
			sock_release(sock);
			sock = NULL;
		}
	}

	return sock;
}



static struct socket *cache_try_connect_state_zsl(struct cache_connection *connection)
{
	const char *what;
	struct socket *msock;
	struct sockaddr_in6 src_in6;
	struct sockaddr_in6 peer_in6;

	int err, peer_addr_len, my_addr_len;
	int sndbuf_size, rcvbuf_size, connect_int = 10;


	my_addr_len = min_t(int, connection->my_state_addr_len, sizeof(src_in6));
	memcpy(&src_in6, &connection->my_state_addr, my_addr_len);

	if (((struct sockaddr *)&connection->my_state_addr)->sa_family == AF_INET6)
		src_in6.sin6_port = 0;
	else
		((struct sockaddr_in *)&src_in6)->sin_port = 0; /* AF_INET & AF_SCI */

	peer_addr_len = min_t(int, connection->peer_state_addr_len, sizeof(src_in6));
	memcpy(&peer_in6, &connection->peer_state_addr, peer_addr_len);

	what = "sock_create_kern";
	err = sock_create_kern(((struct sockaddr *)&src_in6)->sa_family,
			       SOCK_STREAM, IPPROTO_TCP, &msock);
	if (err < 0) {
		msock = NULL;
		goto out;
	}

	msock->sk->sk_rcvtimeo =
	msock->sk->sk_sndtimeo = connect_int * HZ;

	what = "bind before connect";
	err = msock->ops->bind(msock, (struct sockaddr *) &src_in6, my_addr_len);
	if (err < 0)
		goto out;

	what = "connect";
	err = msock->ops->connect(msock, (struct sockaddr *) &peer_in6, peer_addr_len, 0);

out:
	if (err < 0) {		
		cache_dbg("cache_try_connect_state_zsl: %s failed, err = %d\n", what, err);
		if (msock) {
			sock_release(msock);
			msock = NULL;
		}
	}

	cache_dbg("cache_try_connect_state_zsl succeed.\n");
	return msock;
}





static struct socket *cache_try_connect_data_zsl(struct cache_connection *connection)
{
	const char *what;
	struct socket *sock;
	struct sockaddr_in6 src_in6;
	struct sockaddr_in6 peer_in6;

	int err, peer_addr_len, my_addr_len;
	int sndbuf_size, rcvbuf_size, connect_int = 10;


	my_addr_len = min_t(int, connection->my_data_addr_len, sizeof(src_in6));
	memcpy(&src_in6, &connection->my_data_addr, my_addr_len);

	if (((struct sockaddr *)&connection->my_data_addr)->sa_family == AF_INET6)
		src_in6.sin6_port = 0;
	else
		((struct sockaddr_in *)&src_in6)->sin_port = 0; /* AF_INET & AF_SCI */

	peer_addr_len = min_t(int, connection->peer_data_addr_len, sizeof(src_in6));
	memcpy(&peer_in6, &connection->peer_data_addr, peer_addr_len);

	what = "sock_create_kern";
	err = sock_create_kern(((struct sockaddr *)&src_in6)->sa_family,
			       SOCK_STREAM, IPPROTO_TCP, &sock);
	if (err < 0) {
		sock = NULL;
		goto out;
	}

	sock->sk->sk_rcvtimeo =
	sock->sk->sk_sndtimeo = connect_int * HZ;

	what = "bind before connect";
	err = sock->ops->bind(sock, (struct sockaddr *) &src_in6, my_addr_len);
	if (err < 0)
		goto out;

	what = "connect";
	err = sock->ops->connect(sock, (struct sockaddr *) &peer_in6, peer_addr_len, 0);

out:
	if (err < 0) {		
		cache_dbg("cache_try_connect_data_zsl: %s failed, err = %d\n", what, err);
		if (sock) {
			sock_release(sock);
			sock = NULL;
		}
	}
	cache_dbg("cache_try_connect_data_zsl succeed.\n");
	return sock;
}


// zsl: create a state_socket
static struct socket *cache_try_connect_state(struct sockaddr_storage  *my_state_addr, int my_state_addr_len,  struct sockaddr_storage *peer_state_addr, int peer_state_addr_len)
{
	const char *what;
	struct socket *sock;
	struct sockaddr_in6 src_in6;
	struct sockaddr_in6 peer_in6;

	int err, peer_addr_len, my_addr_len;
	int sndbuf_size, rcvbuf_size, connect_int = 10;

/*
	rcu_read_lock();
	nc = rcu_dereference(connection->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return NULL;
	}
	sndbuf_size = nc->sndbuf_size;
	rcvbuf_size = nc->rcvbuf_size;
	connect_int = nc->connect_int;
	rcu_read_unlock();
*/
	my_addr_len = min_t(int, my_state_addr_len, sizeof(src_in6));
	memcpy(&src_in6, &my_state_addr, my_addr_len);

	if (((struct sockaddr *)&my_state_addr)->sa_family == AF_INET6)
		src_in6.sin6_port = 0;
	else
		((struct sockaddr_in *)&src_in6)->sin_port = 0; /* AF_INET & AF_SCI */

	peer_addr_len = min_t(int, peer_state_addr_len, sizeof(src_in6));
	memcpy(&peer_in6, &peer_state_addr, peer_addr_len);

	what = "sock_create_kern";
	err = sock_create_kern(((struct sockaddr *)&src_in6)->sa_family,
			       SOCK_STREAM, IPPROTO_TCP, &sock);
	if (err < 0) {
		sock = NULL;
		goto out;
	}

	sock->sk->sk_rcvtimeo =
	sock->sk->sk_sndtimeo = connect_int * HZ;
//cache_setbufsize(sock, sndbuf_size, rcvbuf_size);

    /* explicitly bind to the configured IP as source IP
	*  for the outgoing connections.
	*  This is needed for multihomed hosts and to be
	*  able to use lo: interfaces for cache.
	* Make sure to use 0 as port number, so linux selects
	*  a free one dynamically.
	*/
	what = "bind before connect";
	err = sock->ops->bind(sock, (struct sockaddr *) &src_in6, my_state_addr_len);
	if (err < 0)
		goto out;

	what = "connect";
	err = sock->ops->connect(sock, (struct sockaddr *) &peer_in6, peer_state_addr_len, 0);

out:
	if (err < 0) {
		if (sock) {
			sock_release(sock);
			sock = NULL;
		}
	}

	return sock;
}



// zsl: create a data_socket
static struct socket *cache_try_connect_data(struct sockaddr_storage  *my_data_addr, int my_data_addr_len,  \
struct sockaddr_storage *peer_data_addr, int peer_data_addr_len)
{
	const char *what;
	struct socket *sock;
	struct sockaddr_in6 src_in6;
	struct sockaddr_in6 peer_in6;

	int err, peer_addr_len, my_addr_len;
	int sndbuf_size, rcvbuf_size, connect_int = 10;

/*
	rcu_read_lock();
	nc = rcu_dereference(connection->net_conf);
	if (!nc) {
		rcu_read_unlock();
		return NULL;
	}
	sndbuf_size = nc->sndbuf_size;
	rcvbuf_size = nc->rcvbuf_size;
	connect_int = nc->connect_int;
	rcu_read_unlock();
*/
	my_addr_len = min_t(int, my_data_addr_len, sizeof(src_in6));
	memcpy(&src_in6, &my_data_addr, my_addr_len);

	if (((struct sockaddr *)&my_data_addr)->sa_family == AF_INET6)
		src_in6.sin6_port = 0;
	else
		((struct sockaddr_in *)&src_in6)->sin_port = 0; /* AF_INET & AF_SCI */

	peer_addr_len = min_t(int, peer_data_addr_len, sizeof(src_in6));
	memcpy(&peer_in6, &peer_data_addr, peer_addr_len);

	what = "sock_create_kern";
	err = sock_create_kern(((struct sockaddr *)&src_in6)->sa_family,
			       SOCK_STREAM, IPPROTO_TCP, &sock);
	if (err < 0) {
		sock = NULL;
		cache_dbg("cache_try_connect_data: %s failed, err = %d\n", what, err);
		goto out;
	}

	sock->sk->sk_rcvtimeo =
	sock->sk->sk_sndtimeo = connect_int * HZ;
//cache_setbufsize(sock, sndbuf_size, rcvbuf_size);

    /* explicitly bind to the configured IP as source IP
	*  for the outgoing connections.
	*  This is needed for multihomed hosts and to be
	*  able to use lo: interfaces for cache.
	* Make sure to use 0 as port number, so linux selects
	*  a free one dynamically.
	*/
	what = "bind before connect";
	err = sock->ops->bind(sock, (struct sockaddr *) &src_in6, my_data_addr_len);
	if (err < 0)
		goto out;

	what = "connect";
	err = sock->ops->connect(sock, (struct sockaddr *) &peer_in6, peer_data_addr_len, 0);

out:
	if (err < 0) {
		if (sock) {
			sock_release(sock);
			sock = NULL;			
			cache_dbg("cache_try_connect_data: %s failed, err = %d\n", what, err);
		}
	}

	return sock;
}





//建立服务器端
static int prepare_listen_socket(struct cache_connection *connection, struct accept_wait_data *ad)
{
	int err, my_addr_len;
//	int sndbuf_size, rcvbuf_size,
	struct sockaddr_in6 my_addr;
	struct socket *s_data_listen;
	struct socket *s_state_listen;
	
	const char *what;
	int ping_timeo = 10;

	int my_state_addr_len, my_data_addr_len;
	struct sockaddr_in6 my_state_addr, my_data_addr;

	my_data_addr_len = min_t(int, connection->my_data_addr_len, sizeof(struct sockaddr_in6));
	memcpy(&my_data_addr, &connection->my_data_addr, my_data_addr_len);
	my_state_addr_len = min_t(int, connection->my_state_addr_len, sizeof(struct sockaddr_in6));
	memcpy(&my_state_addr, &connection->my_state_addr, my_state_addr_len);	

	what = "sock_create_kern";
	err = sock_create_kern(((struct sockaddr *)&my_data_addr)->sa_family,
			       SOCK_STREAM, IPPROTO_TCP, &s_data_listen);
	if (err) {
		s_data_listen = NULL;
		goto out;
	}

	err = sock_create_kern(((struct sockaddr *)&my_state_addr)->sa_family,
			       SOCK_STREAM, IPPROTO_TCP, &s_state_listen);
	if (err) {
		s_state_listen = NULL;
		goto out;
	}

	s_data_listen->sk->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */
	s_state_listen->sk->sk_reuse = SK_CAN_REUSE; /* SO_REUSEADDR */
	//cache_setbufsize(s_listen, sndbuf_size, rcvbuf_size);

	s_state_listen->sk->sk_sndtimeo =
	s_state_listen->sk->sk_rcvtimeo = ping_timeo*4*HZ/10;
	s_data_listen->sk->sk_sndtimeo =
	s_data_listen->sk->sk_rcvtimeo = ping_timeo*4*HZ/10;

	

	what = "bind before listen";
	err = s_data_listen->ops->bind(s_data_listen, (struct sockaddr *)&my_data_addr, my_data_addr_len);
	if (err < 0)
		goto out;
	err = s_state_listen->ops->bind(s_state_listen, (struct sockaddr *)&my_state_addr, my_state_addr_len);
	if (err < 0)
		goto out;

	ad->s_data_listen = s_data_listen;
	ad->s_state_listen = s_state_listen;
/*
	write_lock_bh(&s_listen->sk->sk_callback_lock);
	ad->original_sk_state_change = s_listen->sk->sk_state_change;
	s_listen->sk->sk_state_change = cache_incoming_connection;
	s_listen->sk->sk_user_data = ad;
	write_unlock_bh(&s_listen->sk->sk_callback_lock);
*/
	what = "listen";
	err = s_state_listen->ops->listen(s_state_listen, 5);
	if (err < 0)
		goto out;
	err = s_data_listen->ops->listen(s_data_listen, 5);
	if (err < 0)
		goto out;

	cache_dbg("zsl: prepare_listen_socket succeed.\n");
	return 0;
out:
	if (s_state_listen){
		sock_close(s_state_listen);
	}
	
	if(s_data_listen){
		sock_close(s_data_listen);
	}
	
	if (err < 0) {
		if (err != -EAGAIN && err != -EINTR && err != -ERESTARTSYS) {
			cache_dbg("server: prepare_listen_socket : %s failed, err = %d\n", what, err);
		}
	}
	return -EIO;
}

/*
 * return values:
 *   1 yes, we have a valid connection
 *   0 oops, did not work out, please try again
 *  -1 peer talks different language,
 *     no point in trying again, please go standalone.
 *  -2 We do not have a network config...
 */
static int conn_connect(struct cache_connection *connection)
{
	struct cache_socket sock, msock;
	int timeout = 60, h = 0, ok;
	int ping_timeo = 5;
	int err;

	struct accept_wait_data ad = {
		.connection = connection,
		.door_bell = COMPLETION_INITIALIZER_ONSTACK(ad.door_bell), //non-used, just ignore it ...
	};

	mutex_init(&sock.mutex);
	sock.sbuf = connection->data.sbuf;
	sock.rbuf = connection->data.rbuf;
	sock.socket = NULL;
	mutex_init(&msock.mutex);
	msock.sbuf = connection->state.sbuf;
	msock.rbuf = connection->state.rbuf;
	msock.socket = NULL;

	if (prepare_listen_socket(connection, &ad))
		return -1;

	do {
		//struct socket *s;
		struct socket *s_data;
		struct socket *s_state;

		//s = cache_try_connect(connection);
		//s_data = cache_try_connect_data(&connection->my_data_addr, \
			//&connection->my_data_addr_len, &connection->peer_data_addr, &connection->peer_data_addr_len);
		//s_state = cache_try_connect_state(&connection->my_state_addr, \ 
			//&connection->my_state_addr_len, &connection->peer_state_addr, &connection->peer_state_addr_len);
		//cache_alert("zsl: two sockets: data and state have been built successfully on my first try.\n");
		s_state = cache_try_connect_state_zsl(connection);
		s_data = cache_try_connect_data_zsl(connection);
		
		if (!sock.socket) {
				sock.socket = s_data;
				err = send_first_packet(connection, &sock, P_INITIAL_DATA);
				if(!err)
					cache_dbg("zsl: data_socket: send first data packet succeeful!\n");	
				else
					cache_dbg("zsl: data_socket: send first data packet failed!\n");
		} else if (!msock.socket) {
				msock.socket = s_state;
				err = send_first_packet(connection, &msock, P_INITIAL_META);
				if(!err)
					cache_dbg("zsl: state_cache: send first packet succeeful!\n");
				else	
					cache_dbg("zsl: state_socket: send first state packet failed!\n");
		} else {
				cache_err("Logic error in conn_connect()\n");
				goto out_release_sockets;
		}
		



		if (sock.socket && msock.socket) {
			timeout = ping_timeo * HZ / 10;
			schedule_timeout_interruptible(timeout);
			ok = cache_socket_okay(&sock.socket);
			ok = cache_socket_okay(&msock.socket) && ok;
			if (ok){
				cache_dbg("zsl: ok!\n");
				break;
				}
		}

retry:
		if (get_t_state(&connection->receiver) == EXITING)
			goto out_release_sockets;

		s_data = cache_wait_for_data_connect(connection, &ad);
		s_state= cache_wait_for_state_connect(connection, &ad);

		if (s_data) {
			int fp = receive_first_packet(connection, s_data);

			if(fp == P_INITIAL_DATA){
				if(sock.socket){
					sock_release(sock.socket);
					sock.socket = s_data;
					if (prandom_u32() & 1)
					goto retry;	
				}
				else{
					sock.socket = s_data;
					cache_dbg("zsl: receiving initial data packet...\n");
				}			
			}
		}

		if (s_state) {
			int fp = receive_first_packet(connection, s_state);

			if(fp == P_INITIAL_META){
				if(msock.socket){
					sock_release(msock.socket);
					msock.socket = s_state;
					if (prandom_u32() & 1)
					goto retry;	
				}
				else{
					msock.socket = s_state;
					cache_dbg("zsl: receiving initial state packet...\n");
				}			
			}
		}
					



		if (signal_pending(current)) {
			flush_signals(current);
			smp_rmb();
			if (get_t_state(&connection->receiver) == EXITING)
				goto out_release_sockets;
		}

		ok = cache_socket_okay(&sock.socket);
		ok = cache_socket_okay(&msock.socket) && ok;
	} while(!ok && get_t_state(&connection->receiver) == RUNNING);
	
	if (get_t_state(&connection->receiver) == EXITING)
		goto out_release_sockets;

	if (ad.s_data_listen)
		sock_close(ad.s_data_listen);
	if (ad.s_state_listen)
		sock_close(ad.s_state_listen);

	// if peer is restarted, change the owner of volume 
	hb_restore_owner();
	
	sock.socket->sk->sk_reuse = SK_CAN_REUSE;
	msock.socket->sk->sk_reuse = SK_CAN_REUSE;

	sock.socket->sk->sk_allocation = GFP_NOIO;
	msock.socket->sk->sk_allocation = GFP_NOIO;


	
	sock.socket->sk->sk_sndtimeo =
	sock.socket->sk->sk_rcvtimeo = ping_timeo*4*HZ/10;

	msock.socket->sk->sk_rcvtimeo = ping_timeo*HZ;
	msock.socket->sk->sk_sndtimeo = timeout * HZ / 10;

	// we don't want delays.
	// we use TCP_CORK where appropriate, though 
	cache_tcp_nodelay(sock.socket);
	cache_tcp_nodelay(msock.socket);

	connection->data.socket = sock.socket;
	connection->state.socket = msock.socket;
	connection->last_received = jiffies;
	if(connection->ko_count < 7)
		connection->ko_count = 7;


	return h;

out_release_sockets:
	if (ad.s_data_listen)
		sock_close(ad.s_data_listen);
	if (ad.s_state_listen)
		sock_close(ad.s_state_listen);
	
	if (sock.socket)
		sock_close(sock.socket);
	if (msock.socket)
		sock_close(msock.socket);
	return -1;
}

static void conn_disconnect(struct cache_connection *connection)
{
	cache_free_sock(&connection->data);
	cache_free_sock(&connection->state);
	
	cache_alert("Connection closed\n");
}

/*
* when peer host crash, wait for peer recover
*/
int cache_receiver(struct cache_thread *thi)
{
	struct cache_connection *connection = thi->connection;
	int err;
	cache_info("receiver thread (re)started\n");

retry:
	do {
		cache_dbg("Try to establish connection.\n");
		err = conn_connect(connection);
	} while (err == -1 && get_t_state(&connection->receiver) == RUNNING);

	cache_alert("zsl: ok, connection is established completely successfully now. HAHAHHAHAHA\n");
	

	if (err == 0) {
		//cache_thread_start(&connection->asender);
		complete(&thi->start);
		cache_socket_receive(connection);
		
		if(get_t_state(&connection->receiver) == RUNNING) {
			cache_free_sock(&connection->data);
			cache_dbg("wait for incoming connection.\n");
			goto retry;
		}
	}
	
	return 0;
}

int cache_mreceiver(struct cache_thread *thi)
{
	int err;
	struct cache_connection *connection = thi->connection;

	cache_info("mreceiver thread (re)started\n");
	
	cache_msocket_receive(connection);
	cache_free_sock(&connection->state);
	
	return err;
}
static struct cache_connection *cache_conn_create(struct dcache *dcache)
{
	struct cache_connection *connection;
	struct sockaddr_in my_data_addr, peer_data_addr, my_state_addr, peer_state_addr;

	connection = kzalloc(sizeof(struct cache_connection), GFP_KERNEL);
	if (!connection)
		return NULL;
	
	connection->dcache = dcache;

	if (cache_alloc_socket(&connection->data))
		goto fail;
	if (cache_alloc_socket(&connection->state))
		goto fail;

	
	connection->cstate = C_STANDALONE;
	mutex_init(&connection->cstate_mutex);
	init_waitqueue_head(&connection->ping_wait);
	kref_init(&connection->kref);
	connection->ko_count = 7;  /* refer to DRBD */

	cache_init_workqueue(&connection->sender_work);
	mutex_init(&connection->data.mutex);
	mutex_init(&connection->state.mutex);

	memset(&my_data_addr, 0, sizeof(my_data_addr));
	memset(&peer_data_addr, 0, sizeof(peer_data_addr));
	memset(&my_state_addr, 0, sizeof(my_state_addr));
	memset(&peer_state_addr, 0, sizeof(peer_state_addr));
	
	connection->my_data_addr_len = sizeof(my_data_addr);
	connection->peer_data_addr_len = sizeof(peer_data_addr);
	connection->my_state_addr_len = sizeof(my_state_addr);
	connection->peer_state_addr_len = sizeof(peer_state_addr);	
	
	atomic_set(&connection->packet_seq, 0);
	
	spin_lock_init(&connection->request_lock);
	atomic_set(&connection->nr_cmnds, 0);
	INIT_LIST_HEAD(&connection->request_list);
	
	my_data_addr.sin_family=AF_INET;
	my_data_addr.sin_addr.s_addr=inet_addr(dcache->inet_data_host_addr);//在这里读取了配置文件
	//设置了IP地址	
	my_data_addr.sin_port=htons(dcache->port);
	memcpy(&connection->my_data_addr, &my_data_addr, sizeof(my_data_addr));
	
	peer_data_addr.sin_family=AF_INET;
	peer_data_addr.sin_addr.s_addr=inet_addr(dcache->inet_data_peer_addr);//在这里读取了配置文件
	//设置了IP地址
	peer_data_addr.sin_port=htons(dcache->port);
	memcpy(&connection->peer_data_addr, &peer_data_addr, sizeof(peer_data_addr));

	
	
	my_state_addr.sin_family=AF_INET;
	my_state_addr.sin_addr.s_addr=inet_addr(dcache->inet_state_host_addr);//在这里读取了配置文件
	//设置了IP地址	
	my_state_addr.sin_port=htons(dcache->port);
	memcpy(&connection->my_state_addr, &my_state_addr, sizeof(my_state_addr));
	
	peer_state_addr.sin_family=AF_INET;
	peer_state_addr.sin_addr.s_addr=inet_addr(dcache->inet_state_peer_addr);//在这里读取了配置文件
	//设置了IP地址
	peer_state_addr.sin_port=htons(dcache->port);
	memcpy(&connection->peer_state_addr, &peer_state_addr, sizeof(peer_state_addr));


	cache_thread_init(&connection->receiver, cache_receiver, "dreceiver");
	connection->receiver.connection = connection;

	cache_thread_init(&connection->asender, cache_mreceiver, "mreceiver");
	connection->asender.connection = connection;

	cache_thread_start(&connection->receiver);
	
	return connection;


	cache_dbg("zsl: cache_conn_create: cache_receiver and cache_mreceiver is ok now.\n");
	return NULL;

fail:
	cache_free_socket(&connection->state);
	cache_free_socket(&connection->data);
	kfree(connection);
	return NULL;
}

static void cache_conn_destroy(struct dcache *dcache)
{
	struct cache_connection *cache_conn;

	if(!dcache)
		return;
	
	if(!(cache_conn = dcache->conn))
		return;

	cache_thread_stop(&cache_conn->receiver);
	cache_thread_stop(&cache_conn->asender);
	
	conn_disconnect(cache_conn);
	cache_free_socket(&cache_conn->state);
	cache_free_socket(&cache_conn->data);
	
	kfree(cache_conn);
	dcache->conn = NULL;
	
	return;
}

void  cache_mesi_lists_init(void)
{

	INIT_LIST_HEAD(&m_list.M_LIST);
	spin_lock_init(&m_list.m_lock);
	
	INIT_LIST_HEAD(&e_list.E_LIST);
	spin_lock_init(&e_list.e_lock);
	
	INIT_LIST_HEAD(&s_list.S_LIST);
	spin_lock_init(&s_list.s_lock);
	
	INIT_LIST_HEAD(&i_list.I_LIST);
	spin_lock_init(&i_list.i_lock);

	INIT_LIST_HEAD(&w_list.W_LIST);
	spin_lock_init(&w_list.w_lock);
}

struct cache_connection *cache_conn_init(struct dcache *dcache)
{
	struct cache_connection * conn;

	cache_alert("Start to init mesi_lists.\n");
	cache_mesi_lists_init();
	cache_alert("Init mesi_lists ok.\n");

	cache_alert("Start connection between caches!\n");
	
	conn = cache_conn_create(dcache);
	
	if(peer_is_good)
		wait_for_completion(&conn->receiver.start);
	
	return conn;
}

int cache_conn_exit(struct dcache *dcache)
{
	cache_conn_destroy(dcache);
	
	cache_dbg("Destroy connection between caches!\n");
	return 0;
}

