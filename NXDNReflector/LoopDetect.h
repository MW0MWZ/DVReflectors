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

#if !defined(LOOPDETECT_H)
#define	LOOPDETECT_H

#include "Timer.h"

#include <chrono>
#include <string>
#include <map>

// Same thresholds as XLXd
const unsigned int LOOP_DETECT_SHORT_MS    = 1000U;	// shorter than this is a short transmission
const unsigned int LOOP_DETECT_GAP_SEC     = 2U;	// max seconds between short transmissions
const unsigned int LOOP_DETECT_SHORT_COUNT = 3U;	// consecutive short transmissions per strike
const unsigned int LOOP_BACKOFF_1_SEC      = 3U;	// strike 1: TX block
const unsigned int LOOP_BACKOFF_2_SEC      = 10U;	// strike 2: TX block
const unsigned int LOOP_BACKOFF_3_SEC      = 300U;	// strike 3: TX block, node removed and link blocked
const unsigned int LOOP_STRIKE_DECAY_SEC   = 300U;	// strikes forgotten after this long clean
const unsigned int LOOP_DROP_LOG_SEC       = 5U;	// min seconds between drop log lines

// Spots loops (runs of short transmissions in quick succession) and
// blocks both the user and the node they came through. Everything is
// keyed by station (base callsign), so users and nodes share blocks:
// M1AB looping blocks M1AB-ND and M1AB-RPT too, but not M1ABC.
class CLoopDetect
{
public:
	CLoopDetect();
	~CLoopDetect();

	// A transmission has started. The node is empty for network sources.
	// NXDN and P25 users are their callsign, or their Id if it isn't known.
	void start(const std::string& user, const std::string& node);

	// The user of the current transmission is now known
	void setUser(const std::string& user);

	// A packet of the current transmission has been forwarded
	void touch();

	// Forget the current transmission without scoring it
	void cancel();

	// The transmission has ended. True if its node must be removed.
	bool end();

	// Is a transmission from this user, or through this node, blocked
	bool check(const std::string& user, const std::string& node);

	// Is this node barred from linking
	bool checkLink(const std::string& node);

	void clock(unsigned int ms);

private:
	typedef std::chrono::steady_clock::time_point TimePoint;

	struct CPenalty {
		CPenalty() : m_strikes(0U), m_lastStrike(), m_blockUntil(), m_linkBlocked(false), m_expiryLog(false), m_lastDropLog(), m_dropLogged(false) {}

		unsigned int m_strikes;
		TimePoint    m_lastStrike;
		TimePoint    m_blockUntil;
		bool         m_linkBlocked;
		bool         m_expiryLog;
		TimePoint    m_lastDropLog;
		bool         m_dropLogged;
	};

	bool        m_active;
	std::string m_user;
	std::string m_node;
	TimePoint   m_start;
	TimePoint   m_last;

	// The last transmission to end
	bool         m_prevValid;
	std::string  m_prevUser;
	TimePoint    m_prevEnd;
	unsigned int m_prevShortCount;

	// Users and nodes, by station
	std::map<std::string, CPenalty> m_penalties;

	CTimer m_purgeTimer;

	bool isBlocked(const std::string& key, const TimePoint& now);
};

#endif
