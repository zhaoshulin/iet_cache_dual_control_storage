/*
 * cache_conn/cache_receiver.c
 *
 * according to cmd, execute corresponding callback(receive different data)
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

#include "../cache_def.h"
#include "../cache.h"
#include "cache_conn.h"
#include "../cache_config.h"

static int decode_header(struct cache_connection *conn, void *header, struct packet_info *pi)
{ /*header=>pi; 移动pi->data指针到结构体那里*/
	unsigned int header_size = cache_header_size(conn);

	if (header_size == sizeof(struct p_header80) &&
		   *(__be16 *)header == cpu_to_be16(CACHE_MAGIC)) {
		struct p_header80 *h = header;
		pi->cmd = be16_to_cpu(h->command);
		pi->size = be32_to_cpu(h->length);
		pi->vnr = 0;
		pi->from = h->from;
		pi->to = h->to;
		cache_dbg("decode_header ok now, magic value = 0x%08x.\n", be16_to_cpu(*(__be16 *)header));
	} else {
		cache_err("Wrong magic value 0x%08x.\n",
			 be16_to_cpu(*(__be16 *)header));
		return -EINVAL;
	}
	pi->data = header + header_size;
	return 0;
}

int cache_recv_short(struct socket *sock, void *buf, size_t size, int flags)
{
	mm_segment_t oldfs;
	struct kvec iov = {
		.iov_base = buf,
		.iov_len = size,
	};
	struct msghdr msg = {
		.msg_iovlen = 1,
		.msg_iov = (struct iovec *)&iov,
		.msg_flags = (flags ? flags : MSG_WAITALL | MSG_NOSIGNAL)
	};
	int rv;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	rv = sock_recvmsg(sock, &msg, size, msg.msg_flags);
	set_fs(oldfs);

	return rv;
}

static int cache_recv(struct cache_socket *cache_socket, void *buf, size_t size)
{
	int rv;

	rv = cache_recv_short(cache_socket->socket, buf, size, 0);

	if (rv < 0) {
		cache_ignore( "sock_recvmsg returned %d\n", rv);
		if (rv == -ECONNRESET)
			cache_info("sock was reset by peer\n");
	} else if (rv == 0) {
		cache_info("sock was shut down by peer\n");
		hb_change_state();
	}
	
	return rv;
}

static int cache_recv_all(struct cache_socket *cache_socket, void *buf, size_t size)
{
	int err;

	err = cache_recv(cache_socket, buf, size);
	if (err != size) {
		if (err >= 0)
			err = -EIO;
	} else
		err = 0;
	return err;
}

static int cache_recv_all_warn(struct cache_socket *cache_socket, void *buf, size_t size)
{ /*socket=>buffer*/
	int err;

	err = cache_recv_all(cache_socket, buf, size);
	if (err && err != -EAGAIN && !signal_pending(current))
		cache_warn("short read (expected size %d)\n", (int)size);
	return err;
}

int cache_recv_header(struct cache_connection *connection, struct cache_socket *cache_socket, 
	struct packet_info *pi)
{/*接收头部；构造pi；移动pi->data指针到结构体那里*/

	void *buffer = cache_socket->rbuf;
	int err;

	err = cache_recv_all_warn(cache_socket, buffer, cache_header_size(connection));
	if (err)
		return err;

	err = decode_header(connection, buffer, pi);
	connection->last_received = jiffies;

	return err;
}

int receive_first_packet(struct cache_connection *connection, struct socket *sock)
{
	unsigned int header_size = cache_header_size(connection);
	struct packet_info pi;
	int err;

	err = cache_recv_short(sock, connection->data.rbuf, header_size, 0);
	if (err != header_size) {
		if (err >= 0)
			err = -EIO;
		return err;
	}
	err = decode_header(connection, connection->data.rbuf, &pi);
	if (err)
		return err;
	return pi.cmd;
}

/* used from receive_Data, with data sock */
static struct cio* read_in_block(struct cache_connection *connection, sector_t sector,
	      struct packet_info *pi)
{
	static struct cio * req; 
	//req用来保护net上的数据
	struct page *page;
	int ds, err;
	int data_size = pi->size;
	int i, nr_pages = (data_size + PAGE_SIZE - 1)>>PAGE_SHIFT;
	unsigned long *data;

	if (!(IS_ALIGNED(data_size, 512))){
		cache_err("size is not aligned to 512.\n");
		return NULL;
	}
	req = cio_alloc(nr_pages);
	if (!req)
		return NULL;
	req->offset = sector << 9;
	req->size = data_size;
	
	ds = data_size;
	
	for(i=0;i<nr_pages; i++){
		unsigned len = min_t(int, ds, PAGE_SIZE);
		page = req->pvec[i];
		data = kmap(page);
		err = cache_recv_all_warn(&connection->data, data, len);
		// connection->data(socket) ---> data(buffer)
		
		kunmap(page);
		if (err) {
			cio_put(req);
			cache_err("Error occurs when receive data from net.\n");
			return NULL;
		}
		ds -= len;
	}

	return req;
}


/* used from receive_Data one page, with data sock */
static struct cio* read_in_page(struct cache_connection *connection, sector_t sector,
	      struct packet_info *pi)
{
	static struct cio * cio; 
	//cio用来保护net上的数据
	struct page *page;
	int ds, err;
	int data_size = pi->size;
	int i, nr_pages = (data_size + PAGE_SIZE - 1)>>PAGE_SHIFT;
	unsigned long *data;

	cache_alert("nr_pages = %d, data_size = %d.\n", nr_pages, data_size);

	if (!(IS_ALIGNED(data_size, 512))){
		cache_err("size is not aligned to 512.\n");
		return NULL;
	}
	cio = cio_alloc(nr_pages);
	if (!cio)
		return NULL;
	cio->offset = sector << 9;
	cio->size = data_size;
	
	ds = data_size;
	
	for(i=0;i<nr_pages; i++){
		unsigned int len = min_t(int, ds, PAGE_SIZE);
		cache_dbg("len = %u\n", len);
		page = cio->pvec[i];
		data = kmap(page);
		err = cache_recv_all_warn(&connection->data, data, len);
		// connection->data(socket) ---> data(buffer)
		
		kunmap(page);
		if (err) {
			cio_put(cio);
			cache_err("Error occurs when receive data from net.\n");
			return NULL;
		}
		ds -= len;
	}

	return cio;
}





/*
* find the exact page pointer, or return NULL 
*/
static struct dcache_page* dcache_find_get_page_zsl(struct dcache *dcache, pgoff_t index)
{
	struct dcache_page * dcache_page;
	void **pagep;
	
	rcu_read_lock();
repeat:
	dcache_page = NULL;
	pagep = radix_tree_lookup_slot(&dcache->page_tree, index);
	if (pagep) {
		dcache_page = radix_tree_deref_slot(pagep);
		if (unlikely(!dcache_page))
			goto out;
		if (radix_tree_deref_retry(dcache_page))
			goto repeat;
		if (unlikely(dcache_page != *pagep)) {
			cache_warn("page has been moved.\n");
			goto repeat;
		}
	}
out:
	rcu_read_unlock();

	return dcache_page;

}


// 根据connection和pi，计算出disk位置，保存在ret 数组中
static int calculate_pos(struct cache_connection *connection, struct packet_info *pi, struct dcache_page **ret)     
{
    struct dcache *dcache = connection -> dcache;
    unsigned int size = pi -> size;
    int count = size / sizeof(pgoff_t);
    pgoff_t *data;
    pgoff_t *pages_index;
    int i, err;
    struct dcache_page *dcache_page;

    data = (pgoff_t *)kzalloc(size, GFP_KERNEL);
    if(!data){
        cache_err("Out of memory!\n");
        return -ENOMEM;
    }

//zsl 这个socket以后要修改
    err = cache_recv_all_warn(&connection->data, data, size);
    if(err){
        cache_err("Error when receiving xxx!\n");
        kfree(data);
        return err;
    }

    pages_index = data;
    for(i = 0; i < count; i ++){
        pgoff_t index = pages_index[i];
        if(index == -1)
            break;
        if(index < 0){
            cache_err("Error: index = %ld.\n");
            kfree(data);
            return -EINVAL;
        }

        dcache_page = dcache_find_get_page_zsl(dcache, index);
        if(!dcache_page){
            cache_alert("page cannot be calculated.\n");
            return 0;
        }
        ret[i++] = dcache_page;
    }
	return 0;
}

void print_mesi_from_to(enum mesi from, enum mesi to)
{
	char *f, *t;

	switch(from){
		case M:
			f = "M";
			break;
		case E:
			f = "E";
			break;
		case S:
			f = "S";
			break;
		case I:
			f = "I";
			break;
		case NEW:
			f = "NEW";
			break;
		case WAITING_ACK:
			f = "WAITING_ACK";
			break;
		default:
			f = "other_state";
			break;
	}

	
	switch(to){
			case M:
				t = "M";
				break;
			case E:
				t = "E";
				break;
			case S:
				t = "S";
				break;
			case I:
				t = "I";
				break;
			case NEW:
				t = "NEW";
				break;
			case WAITING_ACK:
				t = "WAITING_ACK";
				break;
			default:
				t = "other_state";
				break;
		}

	cache_alert("%s ----> %s\n", f, t);
	return;
}

 int is_pos_in_mesi_list(struct page_pos *pos, enum mesi mesi) /*出现了空指针*/
{
	struct page_pos *iterator;
	
	switch(mesi){
		case M:
			spin_lock_irq(&m_list.m_lock);
			list_for_each_entry(iterator,&m_list.M_LIST, list){
				if(pos->page_index == iterator->page_index){
					spin_unlock_irq(&m_list.m_lock);
					cache_alert("in M_list\n");
					return true;
					}
			}
			spin_unlock_irq(&m_list.m_lock);
			cache_alert("not in M_list\n");
			return false;
			
		case E:
			spin_lock_irq(&e_list.e_lock);
			list_for_each_entry(iterator, &e_list.E_LIST, list){
				if(pos->page_index == iterator->page_index){
					spin_unlock_irq(&e_list.e_lock);
					cache_alert("in E_list\n");
					return true;
					}
			}			
			spin_unlock_irq(&e_list.e_lock);
			cache_alert("not in E_list\n");
			return false;

		case S:
			spin_lock_irq(&s_list.s_lock);
			list_for_each_entry(iterator, &s_list.S_LIST, list){
				if(pos->page_index == iterator->page_index){
					spin_unlock_irq(&s_list.s_lock);
					cache_alert("in S_list\n");
					return true;
					}
			}
			spin_unlock_irq(&s_list.s_lock);
			cache_alert("not in S_list\n");
			return false;

		case I:
			spin_lock_irq(&(i_list.i_lock));
			if(list_empty(&(i_list.I_LIST))){
				cache_alert("I list is empty\n");
			}
			
			list_for_each_entry(iterator, &i_list.I_LIST, list){
				if(pos->page_index == iterator->page_index){
					spin_unlock_irq(&i_list.i_lock);
					cache_alert("in I_list\n");
					return true;
				}		
			}
			spin_unlock_irq(&i_list.i_lock);
			cache_alert("not in I_list\n");
			return false;

		case WAITING_ACK:
			spin_lock_irq(&w_list.w_lock);
			list_for_each_entry(iterator, &w_list.W_LIST, list){
				if(pos->page_index == iterator->page_index){
					spin_unlock_irq(&w_list.w_lock);
					cache_alert("in W_list\n");
					return true;
				}		
			}
			spin_unlock_irq(&w_list.w_lock);
			cache_alert("not in W_list\n");
			return false;

		default:
			cache_err("error: it's not mesi list! err input...\n");
			return -EINVAL;
	}	
}

 void add_pos_from_NEW_to_I(struct page_pos *pos) /*有空指针*/
{
	if(is_pos_in_mesi_list(pos, I) == true){
		cache_alert("Logical Error: already in I list, return now\n");
		return;
	}


	spin_lock_irq(&i_list.i_lock);
	list_add(&pos->list, &i_list.I_LIST);
	spin_unlock_irq(&i_list.i_lock);
	cache_alert("add page_pos->index = %ld into I_list.\n", pos->page_index);
	return;
}

void del_pos_from_mesi(struct page_pos *pos, enum mesi from)
{
	if(is_pos_in_mesi_list(pos, from) == false){
		cache_alert("Logic err: page_pos to be deleted is not in this mesi_list!\n");
		return;
	}

	switch(from){
		case M:
			spin_lock_irq(&m_list.m_lock);
			list_del_init(&pos->list);
			spin_unlock_irq(&m_list.m_lock);
			break;

		case E:
			spin_lock_irq(&e_list.e_lock);
			list_del_init(&pos->list);
			spin_unlock_irq(&e_list.e_lock);
			break;

		case S:
			spin_lock_irq(&s_list.s_lock);
			list_del_init(&pos->list);
			spin_unlock_irq(&s_list.s_lock);
			break;

		case I:
			spin_lock_irq(&i_list.i_lock);
			list_del_init(&pos->list);
			spin_unlock_irq(&i_list.i_lock);
			break;

		case WAITING_ACK:
			spin_lock_irq(&w_list.w_lock);
			list_del_init(&pos->list);
			spin_unlock_irq(&w_list.w_lock);
			break;

		default:
			cache_alert("Err input: No such list...\n");
			return;
		
	}
	return;
}

 int move_pos_from_to_zsl(struct page_pos *pos, enum mesi from, enum mesi to)
 {
	int err;
	struct page_pos *iterator;

	/* M->E */
	if(from == M && to == E){
		spin_lock_irq(&m_list.m_lock);
		spin_lock_irq(&e_list.e_lock);
		list_for_each_entry(iterator,&m_list.M_LIST, list){
		//	if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){
		
		if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &e_list.E_LIST);
				spin_unlock_irq(&e_list.e_lock);
				spin_unlock_irq(&m_list.m_lock);
				cache_alert("M -> E \n");
				return 0;
			}						
		}
		spin_unlock_irq(&e_list.e_lock);
		spin_unlock_irq(&m_list.m_lock);
		cache_err("Logical Err: Canot find pos in M list!\n");
		return - EINVAL;
	} 

	/* M->S */
	else if(from == M && to == S){
		spin_lock_irq(&m_list.m_lock);
		spin_lock_irq(&s_list.s_lock);
		list_for_each_entry(iterator, &m_list.M_LIST, list){
		//	if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){	
			if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &s_list.S_LIST);
				spin_unlock_irq(&s_list.s_lock);
				spin_unlock_irq(&m_list.m_lock);
				cache_alert("M -> S \n");
				return 0;
		}
		spin_unlock_irq(&s_list.s_lock);
		spin_unlock_irq(&m_list.m_lock);			
		cache_err("Logical Err: Canot find pos in M list!\n");
		return - EINVAL;
		}
	}

	/* M -> I */
	else if(from == M && to == I){
		spin_lock_irq(&m_list.m_lock);
		spin_lock_irq(&i_list.i_lock);
		list_for_each_entry(iterator, &m_list.M_LIST, list){
			//if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){		
			if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &i_list.I_LIST);
				spin_unlock_irq(&i_list.i_lock);
				spin_unlock_irq(&m_list.m_lock);
				cache_alert("M -> I \n");
				return 0;
		}
		spin_unlock_irq(&i_list.i_lock);
		spin_unlock_irq(&m_list.m_lock);
		cache_err("Logical Err: Canot find pos in M list!\n");
		return - EINVAL;
		}
	}

	/* M -> Waiting_ack*/
	else if(from == M && to == WAITING_ACK){
		spin_lock_irq(&m_list.m_lock);
		spin_lock_irq(&w_list.w_lock);
		list_for_each_entry(iterator, &m_list.M_LIST, list){
			//if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){	
				if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &w_list.W_LIST);
				spin_unlock_irq(&w_list.w_lock);
				spin_unlock_irq(&m_list.m_lock);
				cache_alert("M -> WAITING_ACK \n");
				return 0;
		}
		spin_unlock_irq(&w_list.w_lock);
		spin_unlock_irq(&m_list.m_lock);
		cache_err("Logical Err: Canot find pos in M list!\n");
		return - EINVAL;
		}
	}

	/* E -> M */
	else if(from == E && to == M){
		spin_lock_irq(&m_list.m_lock);
		spin_lock_irq(&e_list.e_lock);
		list_for_each_entry(iterator, &e_list.E_LIST, list){
		//	if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){
			if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &m_list.M_LIST);
				spin_unlock_irq(&e_list.e_lock);
				spin_unlock_irq(&m_list.m_lock);
				cache_alert("E -> M \n");
				return 0;
		}
		spin_unlock_irq(&e_list.e_lock);
		spin_unlock_irq(&m_list.m_lock);
		cache_err("Logical Err: Canot find pos in E list!\n");
		return - EINVAL;
		}
	}

	/* E -> S */
	else if(from == E && to == S){
		spin_lock_irq(&e_list.e_lock);
		spin_lock_irq(&s_list.s_lock);
		list_for_each_entry(iterator, &e_list.E_LIST, list){
			//if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){		
			if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &s_list.S_LIST);
				spin_unlock_irq(&s_list.s_lock);
				spin_unlock_irq(&e_list.e_lock);
				cache_alert("E -> S \n");
				return 0;
		}
		spin_unlock_irq(&s_list.s_lock);
		spin_unlock_irq(&e_list.e_lock);			
		cache_err("Logical Err: Canot find pos in E list!\n");
		return - EINVAL;
		}
	}

	/* E -> I */
	else if(from == E && to == I){
		spin_lock_irq(&e_list.e_lock);
		spin_lock_irq(&i_list.i_lock);
		list_for_each_entry(iterator, &e_list.E_LIST, list){
		//	if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){	
			if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &i_list.I_LIST);
				spin_unlock_irq(&i_list.i_lock);
				spin_unlock_irq(&e_list.e_lock);
				cache_alert("E -> I \n");
				return 0;
		}
		spin_unlock_irq(&i_list.i_lock);
		spin_unlock_irq(&e_list.e_lock);
		cache_err("Logical Err: Canot find pos in E list!\n");
		return - EINVAL;
		}
	}

	/* E -> WAITING_ACK*/
	else if(from == E && to == WAITING_ACK){
		spin_lock_irq(&e_list.e_lock);
		spin_lock_irq(&w_list.w_lock);
		list_for_each_entry(iterator, &e_list.E_LIST, list){
			//if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){	
			if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &w_list.W_LIST);
				spin_unlock_irq(&w_list.w_lock);
				spin_unlock_irq(&e_list.e_lock);
				cache_alert("E -> WAITING_ACK \n");
				return 0;
		}
		spin_unlock_irq(&w_list.w_lock);
		spin_unlock_irq(&e_list.e_lock);
		cache_err("Logical Err: Canot find pos in E list!\n");
		return - EINVAL;
		}
	}

	/* S -> M */
	else if(from == S && to == M){
		spin_lock_irq(&m_list.m_lock);
		spin_lock_irq(&s_list.s_lock);
		list_for_each_entry(iterator, &s_list.S_LIST, list){
			//if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){
			
			if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &m_list.M_LIST);
				spin_unlock_irq(&s_list.s_lock);
				spin_unlock_irq(&m_list.m_lock);
				cache_alert("S -> M \n");
				return 0;
		}
		spin_unlock_irq(&s_list.s_lock);
		spin_unlock_irq(&m_list.m_lock);
		cache_err("Logical Err: Canot find pos in S list!\n");
		return - EINVAL;
		}
	}

	/* S -> E*/
	else if(from == S && to == E){
		spin_lock_irq(&e_list.e_lock);
		spin_lock_irq(&s_list.s_lock);
		list_for_each_entry(iterator, &s_list.S_LIST, list){
			//if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){
			
			if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &e_list.E_LIST);
				spin_unlock_irq(&s_list.s_lock);
				spin_unlock_irq(&e_list.e_lock);
				cache_alert("S -> E \n");
				return 0;
		}
		spin_unlock_irq(&s_list.s_lock);
		spin_unlock_irq(&e_list.e_lock);
		cache_err("Logical Err: Canot find pos in S list!\n");
		return - EINVAL;
		}
	}

	/* S -> I*/
	else if(from == S && to == I){
		spin_lock_irq(&s_list.s_lock);
		spin_lock_irq(&i_list.i_lock);
		list_for_each_entry(iterator, &s_list.S_LIST, list){
			//if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){
			
			if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &i_list.I_LIST);
				spin_unlock_irq(&i_list.i_lock);
				spin_unlock_irq(&s_list.s_lock);
				cache_alert("S -> I \n");
				return 0;
		}
		spin_unlock_irq(&i_list.i_lock);
		spin_unlock_irq(&s_list.s_lock);
		cache_err("Logical Err: Canot find pos in S list!\n");
		return - EINVAL;
		}
	}

	/* S -> W */
	else if(from == S && to == WAITING_ACK){
		spin_lock_irq(&s_list.s_lock);
		spin_lock_irq(&w_list.w_lock);
		list_for_each_entry(iterator, &s_list.S_LIST, list){
			//if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){
			
			if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &w_list.W_LIST);
				spin_unlock_irq(&w_list.w_lock);
				spin_unlock_irq(&s_list.s_lock);
				cache_alert("S -> WAITING_ACK \n");
				return 0;
		}
		spin_unlock_irq(&w_list.w_lock);
		spin_unlock_irq(&s_list.s_lock);
		cache_err("Logical Err: Canot find pos in S list!\n");
		return - EINVAL;
		}
	}

	/* I -> M*/
	else if(from == I && to == M){
		spin_lock_irq(&m_list.m_lock);
		spin_lock_irq(&i_list.i_lock);
		list_for_each_entry(iterator, &i_list.I_LIST, list){
			//if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){
			
			if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &m_list.M_LIST);
				spin_unlock_irq(&i_list.i_lock);
				spin_unlock_irq(&m_list.m_lock);
				cache_alert("I -> M \n");
				return 0;
		}
		spin_unlock_irq(&i_list.i_lock);
		spin_unlock_irq(&m_list.m_lock);
		cache_err("Logical Err: Canot find pos in I list!\n");
		return - EINVAL;
		}
	}

	/* I -> E*/
	else if(from == I && to == E){
		spin_lock_irq(&e_list.e_lock);
		spin_lock_irq(&i_list.i_lock);
		list_for_each_entry(iterator, &i_list.I_LIST, list){
			//if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){
			
			if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &e_list.E_LIST);
				spin_unlock_irq(&i_list.i_lock);
				spin_unlock_irq(&e_list.e_lock);
				cache_alert("I -> E \n");
				return 0;
		}
		spin_unlock_irq(&i_list.i_lock);
		spin_unlock_irq(&e_list.e_lock);			
		cache_err("Logical Err: Canot find pos in I list!\n");
		return - EINVAL;
		}
	}

	/* I -> S*/
	else if(from == I && to == S){
		spin_lock_irq(&s_list.s_lock);
		spin_lock_irq(&i_list.i_lock);
		list_for_each_entry(iterator, &i_list.I_LIST, list){
			//if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){
			
			if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &s_list.S_LIST);
				spin_unlock_irq(&i_list.i_lock);
				spin_unlock_irq(&s_list.s_lock);
				cache_alert("I -> S \n");
				return 0;
		}
		spin_unlock_irq(&i_list.i_lock);
		spin_unlock_irq(&s_list.s_lock);
		cache_err("Logical Err: Canot find pos in I list!\n");
		return - EINVAL;
		}
	}

	/* I -> WAITING_ACK*/
	else if(from == I && to == WAITING_ACK){
		spin_lock_irq(&i_list.i_lock);
		spin_lock_irq(&w_list.w_lock);
		list_for_each_entry(iterator, &i_list.I_LIST, list){
		//	if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){
		
		if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &w_list.W_LIST);
				spin_unlock_irq(&w_list.w_lock);
				spin_unlock_irq(&i_list.i_lock);
				cache_alert("I -> S \n");
				return 0;
		}
		spin_unlock_irq(&w_list.w_lock);
		spin_unlock_irq(&i_list.i_lock);
		cache_err("Logical Err: Canot find pos in I list!\n");
		return - EINVAL;
		}
	}

	/* WAITING_ACK -> M */
	else if(from == WAITING_ACK && to == M){
		spin_lock_irq(&m_list.m_lock);
		spin_lock_irq(&w_list.w_lock);
		list_for_each_entry(iterator, &w_list.W_LIST, list){
			//if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){
			
			if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &m_list.M_LIST);
				spin_unlock_irq(&w_list.w_lock);
				spin_unlock_irq(&m_list.m_lock);
				cache_alert("WAITING_ACK -> M \n");
				return 0;
		}
		spin_unlock_irq(&w_list.w_lock);
		spin_unlock_irq(&m_list.m_lock);
		cache_err("Logical Err: Canot find pos in WAITING_ACK list!\n");
		return - EINVAL;
		}
	}


	/*WAINTING_ACK -> E*/
	else if(from == WAITING_ACK && to == E){
		spin_lock_irq(&e_list.e_lock);
		spin_lock_irq(&w_list.w_lock);
		cache_alert("have got e_lock and w_lock\n");
		list_for_each_entry(iterator, &w_list.W_LIST, list){
			//if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){
			cache_alert("going through w_list...\n");
			if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &e_list.E_LIST);
				spin_unlock_irq(&w_list.w_lock);
				spin_unlock_irq(&e_list.e_lock);
				cache_alert("WAITING_ACK -> E \n");
				return 0;
		}
		spin_unlock_irq(&w_list.w_lock);
		spin_unlock_irq(&e_list.e_lock);
		cache_err("Logical Err: Canot find pos in WAITING_ACK list!\n");
		return - EINVAL;
		}
	}

	/*WATING_ACK -> S */
	else if(from == WAITING_ACK && to == S){
		spin_lock_irq(&s_list.s_lock);
		spin_lock_irq(&w_list.w_lock);
		list_for_each_entry(iterator, &w_list.W_LIST, list){
			//if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){
			if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &s_list.S_LIST);
				spin_unlock_irq(&w_list.w_lock);
				spin_unlock_irq(&s_list.s_lock);
				cache_alert("WAITING_ACK -> S \n");
				return 0;
		}
		spin_unlock_irq(&w_list.w_lock);
		spin_unlock_irq(&s_list.s_lock);
		cache_err("Logical Err: Canot find pos in WAITING_ACK list!\n");
		return - EINVAL;
		}
	}

	/*WAITING_ACK -> I */
	else if(from == WAITING_ACK && to == I){
		spin_lock_irq(&i_list.i_lock);
		spin_lock_irq(&w_list.w_lock);
		list_for_each_entry(iterator, &w_list.W_LIST, list){
			//if(pos->page_index == iterator->page_index && pos->dcache == iterator->dcache){
			
			if(pos->page_index == iterator->page_index){
				list_move(&iterator->list, &i_list.I_LIST);
				spin_unlock_irq(&w_list.w_lock);
				spin_unlock_irq(&i_list.i_lock);
				cache_alert("WAITING_ACK -> I \n");
				return 0;
		}
		spin_unlock_irq(&w_list.w_lock);
		spin_unlock_irq(&i_list.i_lock);
		cache_err("Logical Err: Canot find pos in WAITING_ACK list!\n");
		return - EINVAL;
		}
	}

	else{
		cache_err("Err input, from and to got confused!\n");
		return -EINVAL;
	}
	
 }

 int is_page_in_mesi_list(struct dcache_page *dcache_page, enum mesi from)
 {
	struct dcache_page *iterator;

	if(from == E){
		spin_lock_irq(&e_list.e_lock);
		list_for_each_entry(iterator, &e_list.E_LIST, mesi_list){
			if(dcache_page->dcache == iterator->dcache && dcache_page->index == iterator->index){
				cache_alert("this page is in E_list\n");
				spin_unlock_irq(&e_list.e_lock);
				return true;
			}
		}
		spin_unlock_irq(&e_list.e_lock);
		cache_alert("this page isnot in E_list\n");
		return false;
	}

	else if(from == S){
		spin_lock_irq(&s_list.s_lock);
		list_for_each_entry(iterator, &s_list.S_LIST, mesi_list){
			if(dcache_page->dcache == iterator->dcache && dcache_page->index == iterator->index){
				cache_alert("this page is in S_list\n");
				spin_unlock_irq(&s_list.s_lock);
				return true;
			}
		}
		spin_unlock_irq(&s_list.s_lock);
		cache_alert("this page isnot in S_list\n");
		return false;
	}

	else if(from == WAITING_ACK){
		spin_lock_irq(&w_list.w_lock);
		list_for_each_entry(iterator, &w_list.W_LIST, mesi_list){
			if(dcache_page->dcache == iterator->dcache && dcache_page->index == iterator->index){
				cache_alert("this page is in W_list\n");
				spin_unlock_irq(&w_list.w_lock);
				return true;
			}
		}
		spin_unlock_irq(&w_list.w_lock);
		cache_alert("this page isnot in W_list\n");
		return false;
	}

	else{
		cache_err("Err inputs: not E S WAITING_ACK\n");
		return -EINVAL;
	}
 }

 /**
 * Have to already hold the page_lock before use this function.
 * Also, this dcache_page must have been built already.
 */
int move_page_from_to(struct dcache_page *dcache_page, enum mesi from, enum mesi to)
{
	struct dcache_page *iterator;
	
	if(from == E && to == S){
	/* E -> S */
	spin_lock_irq(&e_list.e_lock);
	spin_lock_irq(&s_list.s_lock);
	cache_alert("have got e_lock and s_lock\n");
	list_for_each_entry(iterator, &e_list.E_LIST, mesi_list){
		cache_dbg("going through e_list...\n");
		if(dcache_page->dcache == iterator->dcache && dcache_page->index == iterator->index){
			list_move(&iterator->mesi_list, &s_list.S_LIST);
			spin_unlock_irq(&s_list.s_lock);
			spin_unlock_irq(&e_list.e_lock);
			cache_alert("have free s_lock and e_lock\n");
			cache_alert("E -> S\n");
			return 0;
		}
	}
	spin_unlock_irq(&s_list.s_lock);
	spin_unlock_irq(&e_list.e_lock);
	cache_err("Logical Err: cannot find dcache_page in E_list!\n");
	return -EINVAL;
	
	}

	else if(from == E && to == WAITING_ACK){
	/* E -> WAITING_ACK */
	spin_lock_irq(&e_list.e_lock);
	spin_lock_irq(&w_list.w_lock);
	cache_alert("have got e_lock and w_lock\n");
	list_for_each_entry(iterator, &e_list.E_LIST, mesi_list){
		cache_dbg("going through e_list...\n");
		if(dcache_page->dcache == iterator->dcache && dcache_page->index == iterator->index){
			list_move(&iterator->mesi_list, &w_list.W_LIST);
			spin_unlock_irq(&w_list.w_lock);
			spin_unlock_irq(&e_list.e_lock);
			cache_alert("have free w_lock and e_lock\n");
			cache_alert("E -> WAITING_ACK\n");
			return 0;
		}
	}
	spin_unlock_irq(&w_list.w_lock);
	spin_unlock_irq(&e_list.e_lock);
	cache_err("Logical Err: cannot find dcache_page in E_list!\n");
	return -EINVAL;	
	}

	else if(from == S && to == E){
	/* S -> E */
	spin_lock_irq(&e_list.e_lock);
	spin_lock_irq(&s_list.s_lock);
	cache_alert("have got e_lock and s_lock\n");
	list_for_each_entry(iterator, &s_list.S_LIST, mesi_list){
		cache_dbg("going through s_list...\n");
		if(dcache_page->dcache == iterator->dcache && dcache_page->index == iterator->index){
			list_move(&iterator->mesi_list, &e_list.E_LIST);
			spin_unlock_irq(&s_list.s_lock);
			spin_unlock_irq(&e_list.e_lock);
			cache_alert("have free s_lock and e_lock\n");
			cache_alert("S -> E\n");
			return 0;
		}
	}
	spin_unlock_irq(&s_list.s_lock);
	spin_unlock_irq(&e_list.e_lock);
	cache_err("Logical Err: cannot find dcache_page in S_list!\n");
	return -EINVAL;	
	}

	else if(from == S && to == WAITING_ACK){
	/* S -> WAITING_ACK */
	spin_lock_irq(&s_list.s_lock);
	spin_lock_irq(&w_list.w_lock);
	cache_alert("have got s_lock and w_lock\n");
	list_for_each_entry(iterator, &s_list.S_LIST, mesi_list){
		cache_dbg("going through s_list...\n");
		if(dcache_page->dcache == iterator->dcache && dcache_page->index == iterator->index){
			list_move(&iterator->mesi_list, &w_list.W_LIST);
			spin_unlock_irq(&w_list.w_lock);
			spin_unlock_irq(&s_list.s_lock);
			cache_alert("have free w_lock and s_lock\n");
			cache_alert("S -> WAITING_ACK\n");
			return 0;
		}
	}
	spin_unlock_irq(&w_list.w_lock);
	spin_unlock_irq(&s_list.s_lock);
	cache_err("Logical Err: cannot find dcache_page in S_list!\n");
	return -EINVAL;	
	}

	else if(from == WAITING_ACK && to == E){
	/* WAITING_ACK -> E */
	spin_lock_irq(&e_list.e_lock);
	spin_lock_irq(&w_list.w_lock);
	cache_alert("have got e_lock and w_lock\n");
	list_for_each_entry(iterator, &w_list.W_LIST, mesi_list){
		cache_dbg("going through w_list...\n");
		if(dcache_page->dcache == iterator->dcache && dcache_page->index == iterator->index){
			list_move(&iterator->mesi_list, &e_list.E_LIST);
			spin_unlock_irq(&w_list.w_lock);
			spin_unlock_irq(&e_list.e_lock);
			cache_alert("have free w_lock and e_lock\n");
			cache_alert("WAITING_ACK -> E\n");
			return 0;
		}
	}
	spin_unlock_irq(&w_list.w_lock);
	spin_unlock_irq(&e_list.e_lock);
	cache_err("Logical Err: cannot find dcache_page in W_list!\n");
	return -EINVAL;	
	}

	else if(from == WAITING_ACK && to == S){
	/* WAITING_ACK -> S */
	spin_lock_irq(&s_list.s_lock);
	spin_lock_irq(&w_list.w_lock);
	cache_alert("have got s_lock and w_lock\n");
	list_for_each_entry(iterator, &w_list.W_LIST, mesi_list){
		cache_dbg("going through w_list...\n");
		if(dcache_page->dcache == iterator->dcache && dcache_page->index == iterator->index){
			list_move(&iterator->mesi_list, &s_list.S_LIST);
			spin_unlock_irq(&w_list.w_lock);
			spin_unlock_irq(&s_list.s_lock);
			cache_alert("have free w_lock and s_lock\n");
			cache_alert("WAITING_ACK -> S\n");
			return 0;
		}
	}
	spin_unlock_irq(&w_list.w_lock);
	spin_unlock_irq(&s_list.s_lock);
	cache_err("Logical Err: cannot find dcache_page in W_list!\n");
	return -EINVAL;	
	}

	else if(from == NIL && to == E){
	/* Nil -> E */
	spin_lock_irq(&e_list.e_lock);
	cache_alert("have got e_lock\n");
	list_add(&dcache_page->mesi_list, &e_list.E_LIST);
	spin_unlock_irq(&e_list.e_lock);
	cache_alert("have free e_lock\n");
	cache_alert("NIL -> E\n");
	return 0;
	}

	else if(from == NIL && to == S){
	/* Nil -> S */
	spin_lock_irq(&s_list.s_lock);
	cache_alert("have got s_lock\n");
	list_add(&dcache_page->mesi_list, &s_list.S_LIST);
	spin_unlock_irq(&s_list.s_lock);
	cache_alert("have free s_lock\n");
	cache_alert("NIL -> S\n");
	return 0;
	}

	else if(from == NIL && to == WAITING_ACK){
	/* Nil -> WAITING_ACK */
	spin_lock_irq(&w_list.w_lock);
	cache_alert("have got w_lock\n");
	list_add(&dcache_page->mesi_list, &w_list.W_LIST);
	spin_unlock_irq(&w_list.w_lock);
	cache_alert("have free w_lock\n");
	cache_alert("NIL -> WAINTING_ACK\n");
	return 0;
	}

	else{
		cache_alert("not used yet \n");
		return 0;
	}
}
 
static int receive_data(struct cache_connection * connection, struct packet_info * pi)
//mesi 在pi中了	
{
	struct dcache *dcache = connection->dcache;
	struct cio * req;
	struct p_data *p = pi->data;
	enum mesi from, to;
	enum rwwb rw;
	struct dcache_page **ret;
	int i, err;
	u32 peer_seq = be32_to_cpu(p->seq_num);
	sector_t sector = be64_to_cpu(p->sector);

	ret = kzalloc((pi->size + 1) * sizeof(struct dcache_page *), GFP_KERNEL);

	from = pi->from;
	to = pi->to;
	rw = p -> rw;

	cache_alert("zsl: start to adjust MESI...\n");
	if(from != I){
		cache_err("err: receive_data(from != I)!!!\n");
		return -EINVAL;
	}

	calculate_pos(connection, pi,ret);//注意:以后要修改，增加错误时回收ret内存

	for(i=0; i < pi->size; i++){
		move_pos_from_to((ret[i]), from,to);
	}
	cache_alert("zsl: adjust MESI finished.\n");
	
	cache_dbg("begin to receive data.\n");	
	req = read_in_block(connection, sector, pi);
	if (!req) {
		cache_err("Error occurs when receive data.\n");
		return -EIO;
	}
	
	cache_dbg("To write received data.\n");
	_dcache_write((void *)dcache, req->pvec, req->pg_cnt, req->size, req->offset, REQUEST_FROM_PEER);

	//cache_send_data_ack(connection,peer_seq, sector);
	//zsl: fix later!!! from = ... to = ...
	//send_data_ack(connection, peer_seq, from, to);
	if(rw == CAUSED_BY_WRITE){
		from = WAITING_ACK;
		to = S;
	}else if(rw == CAUSED_BY_READ){
		from = WAITING_ACK;
		to = E;
	}else{
		cache_err("err: rw_flag isnot READ or WRITE!\n");
		return -EINVAL;
	}

	//send_data_ack(connection, peer_seq, from, to);
	
	
	cio_put(req);
	
	cache_dbg("write received_data into cache finished.\n");
	return 0;
}

static int receive_data_zsl(struct cache_connection * connection, struct packet_info * pi, void* private)
{
	struct dcache *dcache = connection->dcache;
	struct cio * req;
	struct p_data *p = pi->data;
	u32 peer_seq = be32_to_cpu(p->seq_num);
	sector_t sector = be64_to_cpu(p->sector);
	//pgoff_t *page_index;
	//pgoff_t page_index = sector >> SECTORS_ONE_PAGE_SHIFT; 
	pgoff_t page_index;
	struct dcache_page *dcache_page;
	enum mesi from, to;
	enum rwwb rw;
	struct page_pos *page_pos;
	int err;
	
	from = p->from;
	to = p->to;
	rw = p -> rw;
	page_index = p->page_index;
	
	cache_alert("receive_data: from = %d, to = %d, rw = %d, page_index = %ld\n", from, to, rw, page_index);

/**	
	cache_dbg("calculate page_pos based on dcache and page_index...\n");
	dcache_page = dcache_find_get_page_zsl(dcache, page_index);
	if(!dcache_page){
          	cache_dbg("page cannot be found in radix_tree.\n");
		page_pos = kmalloc(sizeof(struct page_pos), GFP_KERNEL);
		page_pos->dcache = dcache;
		page_pos->page_index = page_index;
		spin_lock_irq(&i_list.i_lock);
		list_add(&page_pos->list, &i_list.I_LIST);
		spin_unlock_irq(&i_list.i_lock);
        }
	cache_dbg("calculate page_index ok.\n");

	cache_dbg("start to adjust mesi_lists...\n");
	move_pos_from_to_zsl(page_pos,  pi->from, pi->to);	
	//print_mesi_from_to(pi->from, pi->to);
	cache_dbg("adjust mesi_lists finished now.\n");

**/


	cache_alert("start to receive data...\n");
	req = read_in_page(connection, sector, pi);
	if (!req) {
		cache_err("Error occurs when receive data.\n");
		return -EIO;
	}
	cache_alert("finish recving data.\n");



	
	cache_alert("To write received data.\n");
	_dcache_write((void *)dcache, req->pvec, req->pg_cnt, req->size, req->offset, REQUEST_FROM_PEER);
	cache_alert("write received data finished now.\n");



	cache_alert("To move_page_from_to.\n");
	dcache_page = dcache_find_get_page_zsl(dcache, page_index);
	if(!dcache_page){
		cache_err("page cannot be found in radix_tree!\n");
		return -EINVAL;
	}else{
		lock_page(dcache_page->page);
		cache_alert("page has been found in radix_tree, and have got its page_lock.\n");
	}
	
	move_page_from_to(dcache_page, from, to);
	cache_alert("finish move_page_from_to.\n");

	

	
	cache_alert("start to send_data_ack...\n");
	//cache_send_data_ack(connection, peer_seq, sector);
	if(rw == CAUSED_BY_WRITE){
		from = WAITING_ACK;
		to = S;
	}else if(rw == CAUSED_BY_READ){
		from = WAITING_ACK;
		to = E;
	}else{
		cache_err("err: rw_flag isnot READ or WRITE!\n");
		return -EINVAL;
	}
	send_data_ack_zsl(connection, page_index, peer_seq, sector, from, to);	
	unlock_page(dcache_page->page);
	cache_alert("send_data_ack finished now.\n");



	kfree(pi->data);
	kfree(pi);
	cio_put(req);
	
	cache_dbg("write received data into cache.\n");
	
	return 0;
}

static int receive_state_zsl(struct cache_connection * connection, struct packet_info * pi, void* private)
{
		struct dcache *dcache = connection->dcache;
		struct cache_request * req;
		struct p_state*p= pi->data;
		enum mesi from, to;
		enum rwwb rw;
		int err;
		u32 seq_num = be32_to_cpu(p->seq_num);
		sector_t sector = be64_to_cpu(p->sector);
		//pgoff_t page_index = sector >> SECTORS_ONE_PAGE_SHIFT; 
		pgoff_t *page_index;
		struct dcache_page *dcache_page;
		struct page_pos *page_pos, *reverse_pos;

		if(!pi->data){
			cache_err("pi->data == NULL!\n");
			return -EINVAL;
		}
		
		from = p->from;
		to = p->to;
		rw = p->rw;
	//	cache_alert("receive_state: from = %d, to = %d, rw = %d, seq = %u.\n", from, to, rw, p->seq_num);
		//cache_alert("recved using pi->data: from = %d, to = %d, rw = %d\n", ((struct p_state*)(pi->data))->from, ((struct p_state*)(pi->data))->to, ((struct p_state*)(pi->data))->rw);

		
		page_index = (pgoff_t *)kzalloc(sizeof(pgoff_t), GFP_KERNEL);
		if(!page_index){
			cache_err("out of memory!\n");
			return -ENOMEM;
		}
		
		cache_dbg("start to receive page_index...\n");
		err = cache_recv_all_warn(&connection->state, page_index, pi->size);
		if(err){
			cache_err("error occusrs when recving page_index...\n");
			kfree(page_index);
			return err;
		}
		else
			cache_dbg("finish recving page_index.\n");


		BUG_ON(private != NULL);
		
		cache_alert("receive state: page_index = %ld\n", *page_index);
		
		cache_dbg("calculate dcache_page based on dcache and page_index...\n");
		dcache_page = dcache_find_get_page_zsl(dcache, *page_index);
		if(!dcache_page){
				cache_dbg("page cannot be found in radix_tree.\n");
				page_pos = kmalloc(sizeof(struct page_pos), GFP_KERNEL);
				page_pos->dcache = dcache;
				page_pos->page_index = *page_index;
				add_pos_from_NEW_to_I(page_pos);
				print_mesi_from_to(NEW, I);

			}
		else{
				page_pos = kmalloc(sizeof(struct page_pos), GFP_KERNEL);
				page_pos->dcache = dcache;
				page_pos->page_index = dcache_page->index;
		}
		cache_dbg("calculate dcache_page ok.\n");

		
		cache_dbg("receive_state: start to adjust mesi_lists...\n");
		if(from != I && from != E && from != S && from != NEW){
			cache_err("err: receive_state(from != I E S NEW)!!!\n");
			return -EINVAL;
		}
		
		if(from == I){
			cache_alert("zsl: I->I, so no need to adjust mesi_lists.\n");
			if(rw == CAUSED_BY_READ){
				send_state_ack_zsl(connection, page_pos->page_index, seq_num, WAITING_ACK, E);
			}else if(rw == CAUSED_BY_WRITE){
				send_state_ack_zsl(connection, page_pos->page_index, seq_num, WAITING_ACK, M);
			}else{
				cache_err("err: rw is not READ or WRITE!\n");
				return -EINVAL;
			}	
			return 0;
	 	}

		if(from != NEW){
			reverse_pos = kmalloc(sizeof(struct page_pos), GFP_KERNEL);
			reverse_pos->dcache = dcache;
			reverse_pos->page_index = dcache_page->index;
			move_pos_from_to_zsl(reverse_pos, from,to);		
			//print_mesi_from_to(from, to);
			cache_dbg("zsl: adjust MESI finished.\n");
		}

		cache_dbg("zsl: adjust MESI finished.\n");		
		

		cache_dbg("start to send_state_ack...\n");
		if(rw == CAUSED_BY_READ){
			
			send_state_ack_zsl(connection, *page_index, seq_num, WAITING_ACK, E);
		}else if(rw == CAUSED_BY_WRITE){
			send_state_ack_zsl(connection, *page_index, seq_num, WAITING_ACK, M);
		}else{
			cache_err("err: rw is not READ or WRITE!\n");
			return -EINVAL;
		}
		cache_dbg("send_state_ack finished.\n");

		return 0;
}

static int receive_state_ack_zsl(struct cache_connection *connection, struct packet_info *pi, void* private)
{
		struct dcache *dcache = connection->dcache;
		struct cache_request * req;
		struct p_state_ack*p = pi->data;
		enum mesi from, to;
		enum rwwb rw;
		u32 seq_num = be32_to_cpu(p->seq_num);
		sector_t sector = be64_to_cpu(p->sector);
		//pgoff_t page_index = sector >> SECTORS_ONE_PAGE_SHIFT; 
		pgoff_t page_index;
		struct dcache_page *dcache_page;
		struct page_pos *reverse_pos;

		BUG_ON(private != NULL);

		from = pi->from;
		to = pi->to;
		//rw = p->rw;
		page_index = p->page_index;
		cache_alert("receive_state_ack: from = %d, to = %d, seq_num = %u, p->seq_num = %u, page_index = %ld\n", from, to, seq_num, p->seq_num, p->page_index);

		cache_dbg("calculate dcache_page based on dcache and page_index...\n");
		dcache_page = dcache_find_get_page_zsl(dcache, page_index);
		if(!dcache_page){
				  cache_err("page cannot be calculated.\n");
				return -EINVAL;
		}
		cache_dbg("calculate dcache_page ok.\n");

		cache_dbg("zsl: start to adjust MESI...\n");
		if(from !=WAITING_ACK){
			cache_err("err: receive_data(from != WAITING_ACK)!!!\n");
			return -EINVAL;
		}
	
		reverse_pos = kmalloc(sizeof(struct page_pos), GFP_KERNEL);
		reverse_pos->dcache = dcache;
		reverse_pos->page_index = dcache_page->index;
		move_pos_from_to_zsl(reverse_pos, from,to);
		//print_mesi_from_to(from, to);
		cache_dbg("zsl: adjust mesi_lists finished.\n");

		cache_dbg("before get_ready_request, seq_num = %u\n", seq_num);
		req = get_ready_request(connection, seq_num);
		if(!req)
			return 0;
		else
			cache_dbg("get_ready_request finished now, seq_num = %u req->seq_num = %u\n", seq_num, req->seq_num);
		complete(&req->done);

		cache_dbg("receive_state_ack ok now.\n");
		return 0;
}

static int receive_data_ack_zsl(struct cache_connection *connection, struct packet_info *pi, void* private)
{
			struct dcache *dcache = connection->dcache;
			struct cache_request * req;
			struct p_data_ack*p = pi->data;
			enum mesi from, to;
			enum rwwb rw;
			u32 seq_num = be32_to_cpu(p->seq_num);
			sector_t sector = be64_to_cpu(p->sector);
			pgoff_t page_index = sector >> SECTORS_ONE_PAGE_SHIFT; 
			struct dcache_page *dcache_page;
			struct page_pos *reverse_pos;
	
			BUG_ON(private != NULL);
	
			from = pi->from;
			to = pi->to;
			rw = p->rw;
			cache_dbg("receive_data_ack: from = %d, to = %d, rw = %d.\n", from, to, rw);

			cache_dbg("calculate dcache_page based on dcache and page_index...\n");
			dcache_page = dcache_find_get_page_zsl(dcache, page_index);
			if(!dcache_page){
					  cache_err("page cannot be calculated.\n");
					return -EINVAL;
			}
			cache_dbg("calculate dcache_page ok.\n");
	
			cache_dbg("zsl: start to adjust MESI...\n");
			if(from !=WAITING_ACK){
				cache_err("err: receive_data(from != WAITING_ACK)!!!\n");
				return -EINVAL;
			}

/**
			reverse_pos = kmalloc(sizeof(struct page_pos), GFP_KERNEL);
			reverse_pos->dcache = dcache;
			reverse_pos->page_index = dcache_page->index;
			move_pos_from_to_zsl(reverse_pos, from,to);	
			//print_mesi_from_to(from, to);
			//move_pos_from_to(dcache_page, from, to);

**/
			move_page_from_to(dcache_page, from, to);
			cache_dbg("zsl: adjust mesi_lists finished.\n");
			
			req = get_ready_request(connection, seq_num);
			if(!req)
				return 0;
			complete(&req->done);

			return 0;
}



/* 
* use msock to receive writeback index 
*/
static int receive_wrote_zsl(struct cache_connection *connection, struct packet_info *pi)
{
	struct dcache *dcache = connection->dcache;
	struct p_block_wrote *p = pi->data;
	unsigned int size = pi->size;
	int count = size/sizeof(pgoff_t);
	pgoff_t *data;
	pgoff_t *pages_index;
	u32 peer_seq = be32_to_cpu(p->seq_num);
	int err, i;
	struct list_head *pos, *next;
	struct page_pos *tmp_pos;

	data = (pgoff_t *)kzalloc(size, GFP_KERNEL);
	if (!data){
		cache_err("Out of memory!\n");
		return -ENOMEM;
	}

	cache_alert("begin to receive wrote data.\n");
	
	err = cache_recv_all_warn(&connection->state, data, size);
	if (err) {
		cache_err("Error occurs when receive wrote data...\n");
		kfree(data);
		return err;
	}
	
	pages_index = data;
	for(i=0; i < count; i++) {
		pgoff_t  index = pages_index[i];
		if(index == -1)
			break;
		if(index < 0){
			cache_err("Error occurs, index is %ld.\n", index);
			kfree(data);
			return -EINVAL;
		}
		dcache_clean_page(dcache, index);

/**
		spin_lock_irq(&e_list.e_lock);
		list_for_each_safe(pos, next, &e_list.E_LIST){
			tmp_pos = list_entry(pos, struct page_pos, list);
			if(tmp_pos->page_index == index){
				list_del_init(&tmp_pos->list);
				cache_alert("ok: delete one page_pos in E list\n");
				spin_unlock_irq(&e_list.e_lock);
				goto del_ok;
			}
		}
		spin_unlock_irq(&e_list.e_lock);

		cache_alert("Not in E list, now try S list...\n");
		spin_lock_irq(&s_list.s_lock);
		list_for_each_safe(pos, next, &s_list.S_LIST){
			tmp_pos = list_entry(pos, struct page_pos, list);
			if(tmp_pos->page_index == index){
				list_del_init(&tmp_pos->list);
				cache_alert("ok: delete one page_pos in S list\n");
				spin_unlock_irq(&s_list.s_lock);
				goto del_ok;
			}
		}
		spin_unlock_irq(&s_list.s_lock);
		cache_err("Logic err: wrote_index is not in E and S lists!\n");
		return -EINVAL;
**/


del_ok:
	cache_alert("ok: delete one page_pos in E or S list finished\n");
		
	}

	
	cache_dbg("start to send_wrote_ack...\n");
	cache_send_wrote_ack(connection,peer_seq);
	cache_dbg("finish send_wrote_ack.\n");

	cache_dbg("delete wrote data from cache.\n");

	kfree(data);
	return err;
}



static int receive_wrote_ack_zsl(struct cache_connection *connection, struct packet_info *pi)
{
	struct cache_request * req;
	struct p_wrote_ack *p = pi->data;
	u32 seq_num = be32_to_cpu(p->seq_num);

	cache_alert("Have received wrote ack.\n");
	req = get_ready_request(connection, seq_num);
	if(!req)
		return 0;

	complete(&req->done);

	
	
	return 0;
}




static int receive_state(struct cache_connection * connection, struct packet_info * pi)
//mesi 在pi中了	
{
	struct dcache *dcache = connection->dcache;
	struct cio * req;
	struct p_data *p = pi->data;
	enum mesi from, to;
	enum rwwb rw;
	struct dcache_page **ret;
	int i;
	u32 peer_seq = be32_to_cpu(p->seq_num);
	sector_t sector = be64_to_cpu(p->sector);

	ret = kzalloc((pi->size + 1) * sizeof(struct dcache_page *), GFP_KERNEL);

	from = pi->from;
	to = pi->to;
	rw = p -> rw;
	

	

	cache_alert("zsl: start to adjust MESI...\n");
	if(from != I && from != E && from != S && from != NEW){
		cache_err("err: receive_data(from != I E S NEW)!!!\n");
		return -EINVAL;
	}

	calculate_pos(connection, pi,ret);

	if(from == I){
		cache_alert("zsl: I->I, so return now.\n");
		//zsl: fix later!!!
		//send_state_ack();
		if(rw == CAUSED_BY_READ){
			send_state_ack(connection,peer_seq, WAITING_ACK, M);
		}else if(rw == CAUSED_BY_WRITE){
			send_state_ack(connection, peer_seq, WAITING_ACK, E);
		}else{
			cache_err("err: rw is not READ or WRITE!\n");
			return -EINVAL;
		}
		
		return 0;
	}

	if(from != NEW){
		for(i=0; i < pi->size; i++){
			move_pos_from_to((ret[i]), from,to);
		}
		cache_alert("zsl: adjust MESI finished.\n");
	}
	else{// NEW!
		for(i=0; i < pi->size; i++){
			add_pos_from_NEW_to_I((ret[i]));
		}
		cache_alert("zsl: adjust MESI finished.\n");		
	}
	
	// zsl: fix later!!!
	if(rw == CAUSED_BY_READ){
		send_state_ack(connection,peer_seq, WAITING_ACK, M);
	}else if(rw == CAUSED_BY_WRITE){
		send_state_ack(connection, peer_seq, WAITING_ACK, E);
	}else{
		cache_err("err: rw is not READ or WRITE!\n");
		return -EINVAL;
	}


	//cio_put(req);
	
	//cache_dbg("write received_data into cache finished.\n");
	return 0;
}



static int receive_state_ack(struct cache_connection * connection, struct packet_info * pi)
//mesi 在pi中了	
{
	struct dcache *dcache = connection->dcache;
	struct cio * req;
	struct p_state_ack *p = pi->data;
	enum mesi from, to;
	struct dcache_page **ret;
	int i;
	u32 peer_seq = be32_to_cpu(p->seq_num);
	sector_t sector = be64_to_cpu(p->sector);

	ret = kzalloc((pi->size + 1) * sizeof(struct dcache_page *), GFP_KERNEL);

	from = pi->from;
	to = pi->to;

	cache_alert("zsl: start to adjust MESI...\n");
	if(from !=WAITING_ACK){
		cache_err("err: receive_data(from != WAITING_ACK)!!!\n");
		return -EINVAL;
	}

	calculate_pos(connection, pi,ret);


	for(i=0; i < pi->size; i++){
		move_pos_from_to((ret[i]), from,to);
	}

	cache_alert("zsl: adjust MESI finished.\n");

	//send_state_ack(connection,peer_seq, sector);

	//cio_put(req);
	
	//cache_dbg("write received_data into cache finished.\n");
	return 0;
}

static int receive_data_ack(struct cache_connection *connection, struct packet_info *pi)
{
	struct cache_request * req;
	struct p_block_ack *p = pi->data;
	u32 seq_num = be32_to_cpu(p->seq_num);
	enum mesi from;
	enum mesi to;
	struct dcache_page **ret;
	int i;

	
	ret = kzalloc((pi->size + 1) * sizeof(struct dcache_page *), GFP_KERNEL);

	from = pi->from;
	to = pi->to;

	req = get_ready_request(connection, seq_num);
	if(!req)
		return 0;

	complete(&req->done);

	cache_dbg("receive data ack.\n");

	cache_alert("zsl: start to adjust MESI...\n");
	if(from != WAITING_ACK){
		cache_err("err: receive_data_ack(from != WAITING_ACK)!!!\n");
		return -EINVAL;
	}
	
	calculate_pos(connection, pi,ret);
	for(i=0; i < pi->size; i++){
		move_pos_from_to((ret[i]), from, to);
	}
	cache_alert("zsl: adjust MESI finished.\n");
	
	return 0;
}


/* 
* use msock to receive writeback index 
*/
static int receive_wrote(struct cache_connection *connection, struct packet_info *pi)
{
	struct dcache *dcache = connection->dcache;
	struct p_block_wrote *p = pi->data;
	unsigned int size = pi->size;
	int count = size/sizeof(pgoff_t);
	pgoff_t *data;
	pgoff_t *pages_index;
	u32 peer_seq = be32_to_cpu(p->seq_num);
	int err, i;

	data = (pgoff_t *)kzalloc(size, GFP_KERNEL);
	if (!data){
		cache_err("Out of memory!\n");
		return -ENOMEM;
	}

	cache_dbg("begin to receive wrote data.\n");
	
	err = cache_recv_all_warn(&connection->state, data, size);
	if (err) {
		cache_err("Error occurs when receive wrote data...\n");
		kfree(data);
		return err;
	}
	
	pages_index = data;
	for(i=0; i < count; i++) {
		pgoff_t  index = pages_index[i];
		if(index == -1)
			break;
		if(index < 0){
			cache_err("Error occurs, index is %ld.\n", index);
			kfree(data);
			return -EINVAL;
		}
		dcache_clean_page(dcache, index);
	}

	cache_send_wrote_ack(connection,peer_seq);

	cache_dbg("delete wrote data from cache.\n");

	kfree(data);
	return err;
}

static int got_block_ack(struct cache_connection *connection, struct packet_info *pi)
{
	struct cache_request * req;
	struct p_block_ack *p = pi->data;
	u32 seq_num = be32_to_cpu(p->seq_num);

	req = get_ready_request(connection, seq_num);
	if(!req)
		return 0;

	complete(&req->done);

	cache_dbg("receive data ack.\n");
	return 0;
}

static int got_wrote_ack(struct cache_connection *connection, struct packet_info *pi)
{
	struct cache_request * req;
	struct p_wrote_ack *p = pi->data;
	u32 seq_num = be32_to_cpu(p->seq_num);

	req = get_ready_request(connection, seq_num);
	if(!req)
		return 0;

	complete(&req->done);

	cache_dbg("receive wrote ack.\n");
	return 0;
}

static const char *cmdname(enum cache_packet cmd)
{
	/* THINK may need to become several global tables
	 * when we want to support more than
	 * one PRO_VERSION */
	static const char *cmdnames[] = {
		[P_DATA]	        = "Data",
		[P_DATA_WRITTEN]	= "DataWritten",
		[P_DATA_ACK]	        = "DataAck",
		[P_WRITTEN_ACK]	        = "WrittenAck",
		[P_STATE] = "State",
		[P_STATE_ACK] = "StateAck",
	};

	if (cmd == P_INITIAL_META)
		return "InitialMeta";
	if (cmd == P_INITIAL_DATA)
		return "InitialData";
	if (cmd >= ARRAY_SIZE(cmdnames))
		return "Unknown";
	return cmdnames[cmd];
}

static struct data_cmd cache_cmd_handler[] = {
	[P_DATA]	    = { 1, sizeof(struct p_data), receive_data_zsl },
	//[P_DATA_WRITTEN]    = { 1, sizeof(struct p_block_wrote), receive_wrote},
	//[P_DATA_ACK]	    = {0,  sizeof(struct p_block_ack), got_block_ack },
	//[P_WRITTEN_ACK]	    = {0,  sizeof(struct p_wrote_ack), got_wrote_ack },
	[P_DATA_ACK] = {0, sizeof(struct p_data_ack), receive_data_ack_zsl},
	[P_STATE] = {1, sizeof(struct p_state), receive_state_zsl},
	[P_STATE_ACK] = {0, sizeof(struct p_state_ack), receive_state_ack_zsl},
	[P_DATA_WRITTEN] = { 1, sizeof(struct p_block_wrote), receive_wrote_zsl},
	[P_WRITTEN_ACK] = {0,  sizeof(struct p_wrote_ack), receive_wrote_ack_zsl},
};

/**
* it deals with data or data_ack.
*/
void cache_socket_receive(struct cache_connection *connection)
{
	size_t shs; /* sub header size */
	int err;

	while (get_t_state(&connection->receiver) == RUNNING) {
		struct packet_info *pi;
		struct data_cmd *cmd;
		struct cache_work *work;
		struct p_data *p_data;
		struct p_data_ack *p_data_ack;
		struct cio *req;
		
		pi = kmalloc(sizeof(*pi), GFP_KERNEL);
		if(!pi) {
			cache_alert("No free memory.\n");
			return;
		}
		work = kmalloc(sizeof(*work), GFP_KERNEL);
		if(!work) {
			cache_alert("No free memory.\n");
			kfree(pi);
			return;
		}

		/*接收命令，如P_DATA*/
		err = cache_recv_header(connection, &connection->data, pi);
		if(err < 0){
			if (err == -EAGAIN && peer_is_good)
				continue;
			return;
		}
		
		WARN_ON((pi->cmd != P_DATA) && (pi->cmd != P_DATA_ACK));
		cmd = &cache_cmd_handler[pi->cmd];
		if (unlikely(pi->cmd >= ARRAY_SIZE(cache_cmd_handler) || !cmd->fn)) {
			cache_err("Unexpected data packet %s (0x%04x)\n",
				 cmdname(pi->cmd), pi->cmd);
			return;
		}

		shs = cmd->pkt_size;
		cache_dbg("sub header size = %u\n", shs);
		if (pi->size > shs && !cmd->expect_payload) {
			cache_err("No payload expected %s l:%d\n",
				 cmdname(pi->cmd), pi->size);
			return;
		}
		cache_alert("Cache cmd is %s.\n", cmdname(pi->cmd));
		cache_dbg("finish recving cmd.\n");


		/*P_DATA*/
		if(pi->cmd == P_DATA){

			/*接收结构体*/
			p_data = kmalloc(sizeof(*p_data), GFP_KERNEL);
			if(!p_data){
				cache_alert("No free memory.\n");
				kfree(pi);
				kfree(work);
			}

			if(shs){
				err = cache_recv_all_warn(&connection->data, p_data, shs);
				if(err)
					return;
				pi->size -= shs;
			}
			
			pi->data = p_data;
			
			cache_dbg("recved using p_data: from = %d, to = %d, rw = %d\n", p_data->from, p_data->to, p_data->rw);
			cache_dbg("recved using pi->data: from = %d, to = %d, rw = %d\n", ((struct p_data*)(pi->data))->from, ((struct p_data*)(pi->data))->to, ((struct p_data*)(pi->data))->rw);
			cache_dbg("finish recving p_data.\n");



			/*接收纯数据*/
//			cache_dbg("begin to receive data.\n");
//			req = read_in_page(connection, be64_to_cpu(p_data->sector), pi);
//			if (!req) {
//				cache_err("Error occurs when receive data using read_in_page.\n");
//				return;
//			}
//			cache_alert("finish recving data.\n");

			
			/*执行cmd*/
			cache_dbg("start to call cmd(data)...\n");
			err = cmd->fn(connection, pi, NULL);//在这里执行了cmd 命令
			if (err) {
				cache_err("error receiving %s, e: %d l: %d!\n",
					 cmdname(pi->cmd), err, pi->size);
				return;
			}
			cache_dbg("finish calling cmd(data).\n");
			
			work->private = (void *)req;
			work->info = pi;
			work->cb = cmd->fn;
			//cache_queue_work(&connection->sender_work, work);
			}
		else if(pi->cmd == P_DATA_ACK){

			/*接收结构体*/
			p_data_ack = kmalloc(sizeof(*p_data_ack), GFP_KERNEL);
			if(!p_data_ack){
				cache_alert("No free memory.\n");
				kfree(pi);
				kfree(work);
			}
			pi->data = p_data_ack;
			err = cache_recv_all_warn(&connection->data, p_data_ack, shs);
			if (err)
				return;
			pi->size -= shs;
			cache_dbg("finish recving p_data_ack.\n");


			/*执行cmd*/
			cache_dbg("start to call cmd(data_ack)...\n");
			err = cmd->fn(connection, pi, NULL);//在这里执行了cmd 命令
			if (err) {
				cache_err("error receiving %s, e: %d l: %d!\n",
					 cmdname(pi->cmd), err, pi->size);
				return;
			}
			cache_dbg("finish calling cmd(data_ack).\n");
			work->private = (void *)req;
			work->info = pi;
			work->cb = cmd->fn;

		//	cache_queue_work(&connection->sender_work, work);
		}
		
	}
	
	return ;
}

/*
* it deal with state or state_ack:
*/
void cache_msocket_receive(struct cache_connection *connection)
{

	size_t shs; /* sub header size */
	int err = 0;

	while (get_t_state(&connection->asender) == RUNNING) {
		struct packet_info *pi;
		struct data_cmd *cmd;
		struct cache_work *work;
		struct p_state *p_state;
		struct p_state_ack *p_state_ack;
		struct cio *req;

		pi = kmalloc(sizeof(*pi), GFP_KERNEL);
		if(!pi) {
			cache_alert("No free memory.\n");
			return;
		}
		work = kmalloc(sizeof(*work), GFP_KERNEL);
		if(!work) {
			cache_alert("No free memory.\n");
			kfree(pi);
			return;
		}

		

		/*接收命令，如P_STATE*/
		err = cache_recv_header(connection, &connection->state, pi);
		if(err < 0){
			if (err == -EAGAIN && peer_is_good)
				continue;
			goto err_out;
		}
		WARN_ON((pi->cmd != P_STATE) && (pi->cmd != P_STATE_ACK));

		cmd = &cache_cmd_handler[pi->cmd];
		if (unlikely(pi->cmd >= ARRAY_SIZE(cache_cmd_handler) || !cmd->fn)) {
			cache_err("Unexpected state packet %s (0x%04x)\n",
				 cmdname(pi->cmd), pi->cmd);
			goto err_out;
		}

		shs = cmd->pkt_size;
		cache_dbg("sub header size = %u\n", shs);
		if (pi->size > shs && !cmd->expect_payload) {
			cache_err("No payload expected %s l:%d\n",
				 cmdname(pi->cmd), pi->size);
			goto err_out;
		}
		cache_alert("Cache cmd is %s.\n", cmdname(pi->cmd));
		cache_dbg("finish recving header.\n");
		
		/*P_STATE*/
		if(pi->cmd == P_STATE){
			/*接收结构体*/
			//pi->data = p_state;
			//err = cache_recv_all_warn(&connection->state, p_state, shs);

			p_state = kmalloc(sizeof(*p_state), GFP_KERNEL);
			if(!p_state){
				cache_alert("No free memory.\n");
				kfree(pi);
				kfree(work);
			}

			if(shs){
				err = cache_recv_all_warn(&connection->state, p_state, shs);
				if (err)
					goto err_out;
				pi->size -= shs;
			}
			
			pi->data = p_state;
			cache_dbg("recved using p_state: from = %d, to = %d, rw = %d\n", p_state->from, p_state->to, p_state->rw);
			cache_dbg("recved using pi->data: from = %d, to = %d, rw = %d\n", ((struct p_state*)(pi->data))->from, ((struct p_state*)(pi->data))->to, ((struct p_state*)(pi->data))->rw);

			cache_dbg("finish recving p_state.\n");
			
			/*执行cmd*/
			cache_dbg("start to call cmd(state)...\n");
			err = cmd->fn(connection, pi, NULL);
			if (err) {
				cache_err("error receiving %s, e: %d l: %d!\n",
					 cmdname(pi->cmd), err, pi->size);
				return;
			}
			cache_dbg("finish calling cmd(state).\n");
			
			work->private = (void *)req;
			work->info = pi;
			work->cb = cmd->fn;
			//cache_queue_work(&connection->sender_work, work);
			}
				else if(pi->cmd == P_STATE_ACK){
		
					/*接收结构体*/
					p_state_ack = kmalloc(sizeof(*p_state_ack), GFP_KERNEL);
					if(!p_state_ack){
						cache_alert("No free memory.\n");
						kfree(pi);
						kfree(work);
					}
					
					if(shs){
						err = cache_recv_all_warn(&connection->state, p_state_ack, shs);
						if (err)
							goto err_out;
						pi->size -= shs;
					}
					pi->data = p_state_ack;
					cache_dbg("recved p_state_ack: from = %d, to = %d\n", p_state_ack ->from, p_state_ack->to);
					cache_dbg("finish recving p_state_ack.\n");
		
		
				/*执行cmd*/
				cache_dbg("start to call cmd(state_ack)...\n");
				err = cmd->fn(connection, pi, NULL);//在这里执行了cmd 命令
				if (err) {
					cache_err("error receiving %s, e: %d l: %d!\n",
					cmdname(pi->cmd), err, pi->size);
					return;
				}
			cache_dbg("finish calling cmd(state_ack).\n");
			
			work->private = (void *)req;
			work->info = pi;
			work->cb = cmd->fn;
			//cache_queue_work(&connection->sender_work, work);
				}
		}
	
	return;
	
err_out:
	cache_err("Error occurs when receive on msocket.\n");
	return;
}

