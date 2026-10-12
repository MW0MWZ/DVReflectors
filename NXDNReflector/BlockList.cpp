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

#include "BlockList.h"
#include "Callsign.h"
#include "Log.h"

#include <algorithm>

#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cstring>
#include <cctype>

const int BUFFER_SIZE = 500;

// Largest valid Id, all ones means "ALL"
const unsigned int MAX_ID = 0xFFFEU;

CBlockList::CBlockList(const std::string& file, unsigned int time, CNXDNLookup* lookup) :
m_file(file),
m_time(time),
m_lookup(lookup),
m_callsigns(),
m_wildcards(),
m_ids(),
m_blocked(),
m_timer(1000U, time * 60U),
m_checksum(0U),
m_generation(0U)
{
	assert(lookup != NULL);
}

CBlockList::~CBlockList()
{
}

bool CBlockList::start()
{
	loadFile();
	translate();

	m_timer.start();

	return true;
}

bool CBlockList::check(unsigned int id) const
{
	if (m_blocked.count(id) > 0U)
		return true;

	if (m_wildcards.empty())
		return false;

	// Wildcards match the user's callsign or their Id, so * blocks everyone
	char text[10U];
	::sprintf(text, "%u", id);
	std::string callsign = m_lookup->find(id);

	for (std::vector<std::string>::const_iterator it = m_wildcards.cbegin(); it != m_wildcards.cend(); ++it) {
		if (callsignMatches(callsign, *it) || callsignMatches(text, *it))
			return true;
	}

	return false;
}

bool CBlockList::checkCallsign(const std::string& callsign) const
{
	// By station: M1AB blocks M1AB-ND and M1AB-RPT, not M1ABC
	for (std::vector<std::string>::const_iterator it = m_callsigns.cbegin(); it != m_callsigns.cend(); ++it) {
		if (callsignMatches(callsign, *it))
			return true;
	}

	for (std::vector<std::string>::const_iterator it = m_wildcards.cbegin(); it != m_wildcards.cend(); ++it) {
		if (callsignMatches(callsign, *it))
			return true;
	}

	return false;
}

bool CBlockList::clock(unsigned int ms)
{
	m_timer.clock(ms);

	if (m_timer.isRunning() && m_timer.hasExpired()) {
		// Re-translate if either file has changed
		bool changed = loadFile();
		if (changed || m_lookup->getGeneration() != m_generation)
			translate();

		m_timer.start();

		return changed;
	}

	return false;
}

bool CBlockList::loadFile()
{
	FILE* fp = ::fopen(m_file.c_str(), "rt");
	if (fp == NULL) {
		m_checksum = 0U;

		if (!m_callsigns.empty() || !m_wildcards.empty() || !m_ids.empty()) {
			m_callsigns.clear();
			m_wildcards.clear();
			m_ids.clear();
			return true;
		}

		return false;
	}

	char buffer[BUFFER_SIZE];

	// First perform the checksum (Fletcher 16)
	uint16_t sum1 = 0U;
	uint16_t sum2 = 0U;
	while (::fgets(buffer, BUFFER_SIZE, fp) != NULL) {
		for (char* p = buffer; *p != '\0'; p++) {
			sum1 = (sum1 + uint8_t(*p)) % 255U;
			sum2 = (sum2 + sum1) % 255U;
		}
	}

	uint16_t checksum = (sum2 << 8) | sum1;
	if (checksum == m_checksum) {
		::fclose(fp);
		return false;
	}

	m_checksum = checksum;

	// Rewind the file
	::fseek(fp, 0L, SEEK_SET);

	// Read the callsigns and Ids into the arrays
	m_callsigns.clear();
	m_wildcards.clear();
	m_ids.clear();

	while (::fgets(buffer, BUFFER_SIZE, fp) != NULL) {
		// First word only, split as XLXd does on whitespace or a comma. Skip blank lines and comments
		char* entry = ::strtok(buffer, " ,\t\r\n\f\v");
		if (entry == NULL || entry[0U] == '#')
			continue;

		// All digits means an Id, anything else is a callsign
		bool numeric = true;
		for (char* p = entry; *p != '\0'; p++) {
			if (!::isdigit((unsigned char)*p)) {
				numeric = false;
				break;
			}
		}

		if (numeric) {
			unsigned long id = ::strtoul(entry, NULL, 10);
			if (id == 0UL || id > MAX_ID) {
				LogWarning("Block list: %s is not a valid Id, ignoring", entry);
				continue;
			}

			m_ids.push_back((unsigned int)id);
		} else {
			std::string callsign = std::string(entry);

			std::for_each(callsign.begin(), callsign.end(), [](char& c) {
				c = std::toupper(c);
			});

			// Wildcards are matched as users transmit, not translated to Ids
			if (callsign.find('*') != std::string::npos)
				m_wildcards.push_back(callsign);
			else
				m_callsigns.push_back(callsign);
		}
	}

	::fclose(fp);

	return true;
}

// Build the blocked Id set: listed Ids plus every Id of each listed callsign
void CBlockList::translate()
{
	m_generation = m_lookup->getGeneration();

	m_blocked.clear();

	for (std::vector<unsigned int>::const_iterator it = m_ids.cbegin(); it != m_ids.cend(); ++it)
		m_blocked.insert(*it);

	if (!m_callsigns.empty()) {
		if (m_lookup->getCount() == 0U) {
			LogWarning("Blocking users by callsign is not possible, the Id lookup file is not available or is empty, only nodes will be blocked by callsign");
		} else {
			for (std::vector<std::string>::const_iterator it = m_callsigns.cbegin(); it != m_callsigns.cend(); ++it) {
				std::vector<unsigned int> ids = m_lookup->findIds(*it);
				if (ids.empty())
					LogWarning("Block list: no Id found for callsign %s, it will only block a node with that callsign", it->c_str());

				for (std::vector<unsigned int>::const_iterator id = ids.cbegin(); id != ids.cend(); ++id)
					m_blocked.insert(*id);
			}
		}
	}

	LogInfo("Loaded %u callsigns, %u wildcards and %u Ids from the block list, blocking %u Ids plus wildcard matches", (unsigned int)m_callsigns.size(), (unsigned int)m_wildcards.size(), (unsigned int)m_ids.size(), (unsigned int)m_blocked.size());
}
