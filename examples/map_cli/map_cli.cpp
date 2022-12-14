// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2016-2020, Intel Corporation */

#ifdef NVLEAK_SECURE
#include "ctree_map_persistent_secure.hpp"
#else
#include "ctree_map_persistent.hpp"
#endif
#include "ctree_map_transient.hpp"
#include <cstring>
#include <iostream>
#include <libpmemobj++/pool.hpp>
#include <libpmemobj_cpp_examples_common.hpp>
#include <memory>

namespace
{

using pmem::obj::delete_persistent;
using pmem::obj::make_persistent;
using pmem::obj::persistent_ptr;
using pmem::obj::pool;
using pmem::obj::pool_base;
using pmem::obj::transaction;

/* convenience typedefs */
typedef long long value_t;
typedef uint64_t key_type;
typedef examples::ctree_map_p<key_type, value_t> pmap;
typedef examples::ctree_map_transient<key_type, value_t> vmap;

const std::string LAYOUT = "";

/* available map operations */
enum queue_op {
	UNKNOWN_QUEUE_OP,
	MAP_INSERT,
	MAP_INSERT_NEW,
	MAP_GET,
	MAP_REMOVE,
	MAP_REMOVE_FREE,
	MAP_CLEAR,
	MAP_PRINT,

	MAX_QUEUE_OP
};

/* queue operations strings */
const char *ops_str[MAX_QUEUE_OP] = {"",      "insert", "insert_new",
				     "get",   "remove", "remove_free",
				     "clear", "print"};

/*
 * parse_queue_op -- parses the operation string and returns matching queue_op
 */
queue_op
parse_queue_op(const char *str)
{
	for (int i = 0; i < MAX_QUEUE_OP; ++i)
		if (strcmp(str, ops_str[i]) == 0)
			return (queue_op)i;

	return UNKNOWN_QUEUE_OP;
}

struct root {
	persistent_ptr<pmap> ptree;
};

/*
 * printer -- (internal) print the value for the given key
 */
template <typename T>
int
printer(key_type key, T value, void *)
{
	std::cout << "map[" << key << "] = " << *value << std::endl;
	return 0;
}

/*
 * insert -- (internal) insert value into the map
 */
template <typename T>
void
insert(pool_base pop, T &map, char *argv[], int &argn)
{
	map->insert(atoll(argv[argn]), new value_t(atoll(argv[argn + 1])));
	argn += 2;
}

/*
 * remove -- (internal) remove value from map
 */
template <typename T>
void
remove(pool_base pop, T &map, char *argv[], int &argn)
{
	auto val = map->remove(atoll(argv[argn++]));
	if (val) {
		std::cout << *val << std::endl;
		delete val;
	} else {
		std::cout << "Entry not found\n";
	}
}

/*
 * remove -- (internal) remove specialization for persistent ctree
 */
template <>
void
remove<persistent_ptr<pmap>>(pool_base pop, persistent_ptr<pmap> &map,
			     char *argv[], int &argn)
{
	auto val = map->remove(atoll(argv[argn++]));
	if (val) {
		std::cout << *val << std::endl;
		transaction::run(pop, [&] { delete_persistent<value_t>(val); });
	} else {
		std::cout << "Entry not found\n";
	}
}

/*
 * insert -- (internal) insert specialization for persistent ctree
 */
template <>
void
insert<persistent_ptr<pmap>>(pool_base pop, persistent_ptr<pmap> &map,
			     char *argv[], int &argn)
{
	transaction::run(pop, [&] {
		map->insert(atoll(argv[argn]),
			    make_persistent<value_t>(atoll(argv[argn + 1])));
	});
	argn += 2;
}

/*
 * exec_op -- (internal) execute single operation
 */
template <typename K, typename T>
void
exec_op(pool_base pop, T &map, queue_op op, char *argv[], int &argn)
{
	switch (op) {
		case MAP_INSERT_NEW:
			map->insert_new(atoll(argv[argn]),
					atoll(argv[argn + 1]));
			argn += 2;
			break;
		case MAP_INSERT:
			insert(pop, map, argv, argn);
			break;
		case MAP_GET: {
			auto val = map->get(atoll(argv[argn++]));
			if (val)
				std::cout << *val << std::endl;
			else
				std::cout << "key not found\n";
			break;
		}
		case MAP_REMOVE:
			remove(pop, map, argv, argn);
			break;
		case MAP_REMOVE_FREE:
			map->remove_free(atoll(argv[argn++]));
			break;
		case MAP_CLEAR:
			map->clear();
			break;
		case MAP_PRINT:
			map->foreach (printer<typename K::value_type>, nullptr);
			break;
		default:
			throw std::invalid_argument("invalid queue operation");
	}
}
}

int
main(int argc, char *argv[])
{
	if (argc < 4) {
		std::cerr
			<< "usage: " << argv[0]
			<< " file-name <persistent|volatile> [insert <key value>|insert_new <key value>|get <key>|remove <key> | remove_free <key>]"
			<< std::endl;
		return 1;
	}

#ifdef NVLEAK_SECURE
	std::cout << "Using nvleak secure allocator" << std::endl;
#endif

	std::string path = argv[1];
	std::string type = argv[2];

	pool<root> pop;

	try {
		if (file_exists(path.c_str()) != 0) {
			pop = pool<root>::create(path, LAYOUT, PMEMOBJ_MIN_POOL,
						 CREATE_MODE_RW);
		} else {
			pop = pool<root>::open(path, LAYOUT);
		}
	} catch (pmem::pool_error &e) {
		std::cerr << e.what() << std::endl;
		return 1;
	}

	persistent_ptr<root> q;
	try {
		q = pop.root();
	} catch (std::exception &e) {
		std::cerr << e.what() << std::endl;
		try {
			pop.close();
		} catch (const std::logic_error &e) {
			std::cerr << e.what() << std::endl;
		}
		return 1;
	}

	if (!q->ptree) {
		try {
			transaction::run(pop, [&] {
				q->ptree = make_persistent<pmap>();
			});
		} catch (pmem::transaction_error &e) {
			std::cerr << e.what() << std::endl;
			try {
				pop.close();
			} catch (const std::logic_error &e) {
				std::cerr << e.what() << std::endl;
			}
			return 1;
		}
	}

	auto vtree = std::make_shared<vmap>();

	for (int i = 3; i < argc;) {
		queue_op op = parse_queue_op(argv[i++]);
		try {
			if (type == "volatile")
				exec_op<vmap>(pop, vtree, op, argv, i);
			else
				exec_op<pmap>(pop, q->ptree, op, argv, i);
		} catch (std::exception &e) {
			std::cerr << e.what() << std::endl;
			break;
		}
	}

	try {
		pop.close();
	} catch (const std::logic_error &e) {
		std::cerr << e.what() << std::endl;
	}
	return 0;
}
