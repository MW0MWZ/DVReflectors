/*
 *   Copyright (C) 2026 by Andy Taylor MW0MWZ
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#if !defined(CALLSIGN_H)
#define	CALLSIGN_H

#include <string>
#include <cctype>

// Upper case, without the space (or NUL) padding
inline std::string callsignTrim(const std::string& callsign)
{
	std::string::size_type start = callsign.find_first_not_of(std::string(" \0", 2U));
	if (start == std::string::npos)
		return std::string();

	std::string::size_type end = callsign.find_last_not_of(std::string(" \0", 2U));

	std::string call = callsign.substr(start, end - start + 1U);
	for (std::string::iterator it = call.begin(); it != call.end(); ++it)
		*it = std::toupper((unsigned char)*it);

	return call;
}

// The station: the longest letter/digit run holding a digit, every callsign has one but
// -ND, -RPT and /P don't. M1AB-ND, M1AB/P and DL/M1AB are all M1AB, M1ABC and GM1AB aren't.
inline std::string callsignBase(const std::string& callsign)
{
	std::string call = callsignTrim(callsign);

	std::string first;
	std::string best;

	std::string::size_type n = 0U;
	while (n < call.length()) {
		while (n < call.length() && !std::isalnum((unsigned char)call[n]))
			n++;

		std::string::size_type start = n;
		bool digit = false;
		while (n < call.length() && std::isalnum((unsigned char)call[n])) {
			if (std::isdigit((unsigned char)call[n]))
				digit = true;
			n++;
		}

		if (n == start)
			continue;

		std::string run = call.substr(start, n - start);
		if (first.empty())
			first = run;
		if (digit && run.length() > best.length())
			best = run;
	}

	return best.empty() ? first : best;
}

// A block list entry matches its station (M1AB blocks M1AB-ND, not M1ABC), a whole callsign
// exactly, or as in XLXd a * ends a prefix (M1AB* blocks M1ABC, * blocks everyone)
inline bool callsignMatches(const std::string& callsign, const std::string& entry)
{
	std::string::size_type star = entry.find('*');
	if (star != std::string::npos)
		return callsignTrim(callsign).compare(0U, star, entry, 0U, star) == 0;

	return callsignBase(callsign) == entry || callsignTrim(callsign) == entry;
}

#endif
