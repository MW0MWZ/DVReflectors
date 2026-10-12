/*
 *   Copyright (C) 2021 by Jonathan Naylor G4KLX
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

#if !defined(BLOCKLIST_H)
#define	BLOCKLIST_H

#include "NXDNLookup.h"
#include "Timer.h"

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_set>

class CBlockList
{
public:
	CBlockList(const std::string& file, unsigned int time, CNXDNLookup* lookup);
	~CBlockList();

	bool start();

	bool check(unsigned int id) const;

	bool checkCallsign(const std::string& callsign) const;

	bool clock(unsigned int ms);

private:
	std::string                      m_file;
	unsigned int                     m_time;
	CNXDNLookup*                     m_lookup;
	std::vector<std::string>         m_callsigns;
	std::vector<std::string>         m_wildcards;
	std::vector<unsigned int>        m_ids;
	std::unordered_set<unsigned int> m_blocked;
	CTimer                           m_timer;
	uint16_t                         m_checksum;
	unsigned int                     m_generation;

	bool loadFile();
	void translate();
};

#endif
