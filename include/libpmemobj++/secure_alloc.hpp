#ifndef LIBPMEMOBJ_CPP_NVLEAK_SAFE_ALLOC_H
#define LIBPMEMOBJ_CPP_NVLEAK_SAFE_ALLOC_H

#include <bitset>
#include <cassert>
#include <functional>
#include <iostream>
#include <stdexcept>

namespace nvleak
{

constexpr size_t page_shift{12};
constexpr size_t total_nvsec_sets{256};
constexpr size_t max_try_secure_alloc = (total_nvsec_sets << page_shift);
static bool verbose_output_alloc = false;

class page_field {
public:
	std::bitset<total_nvsec_sets> fields;

	page_field()
	{
		fields.reset();
		set_fields(0, fields.size() / 2);
	}

	page_field(size_t beg, size_t end)
	{
		fields.reset();
		set_fields(beg, end);
	}

	/* Return true if ptr is in secure fields, false otherwise */
	const bool
	check_ptr(size_t ptr) const
	{
		auto page_ofs = ptr >> page_shift;
		return this->fields[(page_ofs % total_nvsec_sets)];
	}

private:
	/* Set fields [beg:end) to 1, including beg, excluding end */
	void
	set_fields(size_t beg, size_t end)
	{
		// std::cout << "page_field::set_fields(): " << beg << ", " <<
		// end << std::endl;
		for (auto curr = beg; curr < end; curr++) {
			this->fields.set(curr, true);
		}
	}
};

template <typename F, typename... Args>
decltype(auto)
secure_alloc(F &&f, const page_field &pf, Args &&...args)
{
	assert(pf.fields.count() > 0);

	decltype(f(args...)) res;
	size_t count = 0;

	do {
		res = std::forward<F>(f)(std::forward<Args>(args)...);
		count++;
		if (count > max_try_secure_alloc) {
			throw std::runtime_error(
				"Secure alloc reached max try.");
		}
	} while (!(pf.check_ptr((size_t)res.off)));

	if (verbose_output_alloc) {
		std::cout << "secure_alloc: tried [" << count
			<< "] allocs, finalized at: [" << res.off << "]"
			<< std::endl;
	}
	return res;
}

void set_alloc_print(bool verbose) {
	verbose_output_alloc = verbose;
}

} /* namespace nvleak */

#endif /* LIBPMEMOBJ_CPP_NVLEAK_SAFE_ALLOC_H */
