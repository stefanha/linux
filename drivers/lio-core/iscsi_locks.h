/*********************************************************************************
 * Filename:  iscsi_locks.h
 *
 * $HeadURL: svn://subversion.sbei.com/pyx/target/branches/2.9-linux-iscsi.org/pyx-target/include/iscsi_locks.h $
 *   $LastChangedRevision: 6893 $
 *   $LastChangedBy: nab $
 *   $LastChangedDate: 2007-04-06 16:00:57 -0700 (Fri, 06 Apr 2007) $
 *
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * For further information, contact via email: support@sbei.com
 * SBE, Inc.  San Ramon, California  U.S.A.
 *********************************************************************************/


#ifndef _ISCSI_LOCKS_H_
#define _ISCSI_LOCKS_H_

#include <linux/types.h>
#include <linux/time.h>

typedef struct
{
  int write, read;
  iscsi_lock_t  lock;
} iscsi_rwlock_t;


#define  RW_LOCK_TIMEOUT 60*5*HZ // 5 minutes... snapshot merge and rollback could take a lot of time

#define  REPORT_BUG() ({printk(KERN_CRIT "Bug in %s at %s:%d\n", __func__, __FILE__, __LINE__); dump_stack(); preempt_count() = 0; while(1) schedule(); })
#define  REPORT_TIMEOUT() ({printk(KERN_CRIT "Timeout in %s at %s:%d, start_jiffies=%llu, jiffies=%llu, timeout=%llu \n", __func__, __FILE__, __LINE__, (unsigned long long)start_jiffies, (unsigned long long)get_jiffies_64(), (unsigned long long)timeout); dump_stack(); preempt_count() = 0; while(1) schedule(); })
	

static  inline void RW_LOCK_INIT(iscsi_rwlock_t *lock)  
{
	lock->read=0; 
	lock->write=0; 
	spin_lock_init(&lock->lock); 
}

static  inline void READ_LOCK(iscsi_rwlock_t *lock)     
{
	typeof(jiffies_64) start_jiffies = get_jiffies_64();
	typeof(jiffies_64) timeout = RW_LOCK_TIMEOUT ? (get_jiffies_64() + RW_LOCK_TIMEOUT) : 0;
	while(!timeout || get_jiffies_64() < timeout)
	{
		spin_lock(&lock->lock);
	
		if (lock->write==0)
		{
			lock->read++;
			spin_unlock(&lock->lock);
			return;
		}
		
		spin_unlock(&lock->lock);
		schedule();
	}
	REPORT_TIMEOUT();
}

static  inline void READ_UNLOCK(iscsi_rwlock_t *lock)
{
	spin_lock(&lock->lock);
	
	if (lock->read < 1)
		REPORT_BUG();
	
	lock->read--;
	spin_unlock(&lock->lock);
}

static  inline void WRITE_LOCK(iscsi_rwlock_t *lock) 
{
	typeof(jiffies_64) start_jiffies = get_jiffies_64();
	typeof(jiffies_64) timeout = RW_LOCK_TIMEOUT ? (get_jiffies_64() + RW_LOCK_TIMEOUT) : 0;
	while(!timeout || get_jiffies_64() < timeout)
	{
		spin_lock(&lock->lock);
		
		if (lock->read==0 && lock->write==0)
		{
			lock->write = 1;
			spin_unlock(&lock->lock);
			return;
		}
		
		spin_unlock(&lock->lock);
		schedule();
	}
	REPORT_TIMEOUT();
}


static  inline void WRITE_UNLOCK(iscsi_rwlock_t *lock) 
{
	spin_lock(&lock->lock);
	
	if (lock->write != 1 || lock->read!=0)
		REPORT_BUG();
	
	lock->write=0;
	spin_unlock(&lock->lock);
}

static  inline void SWITCH_TO_READ_LOCK(iscsi_rwlock_t *lock) 
{
	spin_lock(&lock->lock);
	
	if (lock->write != 1 || lock->read !=0)
		REPORT_BUG();
	
	
	lock->write=0;
	lock->read=1;
	spin_unlock(&lock->lock);
}

#endif   /*** _ISCSI_LOCKS_H_ ***/

