/*********************************************************************************
 * Filename:  iscsi_lists.h
 *
 * This file contains the Linked List definitions.
 *
 * $HeadURL: svn://subversion.sbei.com/pyx/target/branches/2.9-linux-iscsi.org/pyx-target/include/iscsi_lists.h $
 *   $LastChangedRevision: 4792 $
 *   $LastChangedBy: rickd $
 *   $LastChangedDate: 2006-08-17 16:04:06 -0700 (Thu, 17 Aug 2006) $
 *
 * Copyright (c) 2003 PyX Technologies, Inc.
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


#ifndef ISCSI_LISTS_H
#define ISCSI_LISTS_H

#define ADD_ENTRY_TO_LIST(e, head, tail)			\
	if (!head && !tail) {					\
		head = tail = e;				\
		e->next = e->prev = NULL;			\
	} else {						\
		tail->next = e;					\
		e->prev = tail;					\
		tail = e;					\
	}

#define ADD_ENTRY_TO_LIST_PREFIX(pre, e, head, tail)		\
	if (!head && !tail) {					\
		head = tail = e;				\
		e->pre##_next = e->pre##_prev = NULL; 		\
	} else {						\
		tail->pre##_next = e;				\
		e->pre##_prev = tail;				\
		tail = e;					\
	}

#define ADD_ENTRY_TO_LIST_NEXT(e, e_new, head, tail)		\
	if (e->next) {						\
		e_new->next = e->next;				\
		e->next->prev = e_new;				\
	}							\
	if (e == tail)						\
		tail = e_new;					\
								\
	e_new->prev = e;					\
	e->next = e_new;

#define ADD_ENTRY_TO_LIST_PREV(e, e_new, head, tail)		\
	if (e->prev) {						\
		e_new->prev = e->prev;				\
		e->prev->next = e_new;				\
	}							\
	if (e == head)						\
		head = e_new;					\
								\
	e_new->next = e;					\
	e->prev = e_new;

#define ADD_ENTRY_TO_LIST_NEXT_PREFIX(pre, e, e_new, head, tail) \
	if (e->pre##_next) {					\
		e_new->pre##_next = e->pre##_next;		\
		e->pre##_next->pre##_prev = e_new;		\
	}							\
	if (e == tail)						\
		tail = e_new;					\
								\
	e_new->pre##_prev = e;					\
	e->pre##_next = e_new;		

#define ADD_ENTRY_TO_LIST_PREV_PREFIX(pre, e, e_new, head, tail) \
	if (e->pre##_prev) {					\
		e_new->pre##_prev = e->pre##_prev;		\
		e->pre##_prev->pre##_next = e_new;		\
	}							\
	if (e == head)						\
		head = e_new;					\
								\
	e_new->pre##_next = e;					\
	e->pre##_prev = e_new;				
	
#define REMOVE_ENTRY_FROM_LIST(e, head, tail)			\
	if (!e->prev && !e->next)				\
		head = tail = NULL;				\
	else {							\
		if (!e->prev) {					\
			e->next->prev = NULL;			\
			head = e->next;				\
			if (!head->next)			\
				tail = head;			\
		} else if (!e->next) {				\
			e->prev->next = NULL;			\
			tail = e->prev;				\
		} else {					\
			e->next->prev = e->prev;		\
			e->prev->next = e->next;		\
		}						\
		e->next = e->prev = NULL;			\
	}

#define REMOVE_ENTRY_FROM_LIST_PREFIX(pre, e, head, tail)	\
	if (!e->pre##_prev && !e->pre##_next)			\
		head = tail = NULL;				\
	else {							\
		if (!e->pre##_prev) {				\
			e->pre##_next->pre##_prev = NULL;	\
			head = e->pre##_next;			\
			if (!head->pre##_next)			\
				tail = head;			\
		} else if (!e->pre##_next) {			\
			e->pre##_prev->pre##_next = NULL;	\
			tail = e->pre##_prev;			\
		} else {					\
			e->pre##_next->pre##_prev = e->pre##_prev; \
			e->pre##_prev->pre##_next = e->pre##_next; \
		}						\
		e->pre##_next = e->pre##_prev = NULL;		\
	}

#endif   /*** ISCSI_LISTS_H ***/

