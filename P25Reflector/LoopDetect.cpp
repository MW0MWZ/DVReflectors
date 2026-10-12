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

#include "LoopDetect.h"
#include "Callsign.h"
#include "Log.h"

using std::chrono::steady_clock;
using std::chrono::seconds;
using std::chrono::milliseconds;
using std::chrono::duration_cast;

CLoopDetect::CLoopDetect() :
m_active(false),
m_user(),
m_node(),
m_start(),
m_last(),
m_prevValid(false),
m_prevUser(),
m_prevEnd(),
m_prevShortCount(0U),
m_penalties(),
m_purgeTimer(1000U, 60U)
{
	m_purgeTimer.start();
}

CLoopDetect::~CLoopDetect()
{
}

void CLoopDetect::start(const std::string& user, const std::string& node)
{
	m_active = true;
	m_user   = callsignBase(user);
	m_node   = callsignBase(node);
	m_start  = steady_clock::now();
	m_last   = m_start;
}

void CLoopDetect::setUser(const std::string& user)
{
	if (m_active)
		m_user = callsignBase(user);
}

void CLoopDetect::touch()
{
	if (m_active)
		m_last = steady_clock::now();
}

void CLoopDetect::cancel()
{
	m_active = false;
}

bool CLoopDetect::end()
{
	if (!m_active)
		return false;

	m_active = false;

	// Never identified, nothing to score
	if (m_user.empty())
		return false;

	// Timed to the last packet, a watchdog ending adds no length
	TimePoint now = steady_clock::now();
	bool isShort = duration_cast<milliseconds>(m_last - m_start).count() < (long long)LOOP_DETECT_SHORT_MS;

	// A short transmission from the same user as the last one, soon after it or while they have live strikes
	bool patternContinues = false;
	if (m_prevValid && m_prevUser == m_user && isShort) {
		bool hasActiveStrikes = false;

		std::map<std::string, CPenalty>::iterator it = m_penalties.find(m_user);
		if (it != m_penalties.end() && it->second.m_strikes > 0U) {
			if (now - it->second.m_lastStrike > seconds(LOOP_STRIKE_DECAY_SEC))
				it->second.m_strikes = 0U;
			else
				hasActiveStrikes = true;
		}

		if (m_last - m_prevEnd < seconds(LOOP_DETECT_GAP_SEC) || hasActiveStrikes)
			patternContinues = true;
	}

	if (patternContinues)
		m_prevShortCount++;
	else
		m_prevShortCount = isShort ? 1U : 0U;

	bool removeNode = false;

	if (patternContinues && m_prevShortCount >= LOOP_DETECT_SHORT_COUNT) {
		CPenalty& user = m_penalties[m_user];

		if (user.m_strikes > 0U && now - user.m_lastStrike > seconds(LOOP_STRIKE_DECAY_SEC))
			user.m_strikes = 0U;

		user.m_strikes++;
		user.m_lastStrike = now;
		user.m_expiryLog  = true;

		// The next strike needs another full run
		m_prevShortCount = 0U;

		unsigned int secs = LOOP_BACKOFF_3_SEC;
		if (user.m_strikes == 1U)
			secs = LOOP_BACKOFF_1_SEC;
		else if (user.m_strikes == 2U)
			secs = LOOP_BACKOFF_2_SEC;

		user.m_blockUntil = now + seconds(secs);

		if (m_node.empty()) {
			LogMessage("Loop detection: %s - strike %u, TX blocked for %us", m_user.c_str(), user.m_strikes, secs);
		} else {
			// The node is blocked alongside the user
			CPenalty& node = m_penalties[m_node];
			if (node.m_blockUntil < user.m_blockUntil)
				node.m_blockUntil = user.m_blockUntil;
			node.m_expiryLog = true;

			if (user.m_strikes >= 3U) {
				node.m_linkBlocked = true;
				removeNode = true;
				LogMessage("Loop detection: %s at %s - strike %u, TX blocked for %us, node removed and link blocked", m_user.c_str(), m_node.c_str(), user.m_strikes, secs);
			} else {
				LogMessage("Loop detection: %s at %s - strike %u, TX blocked for %us", m_user.c_str(), m_node.c_str(), user.m_strikes, secs);
			}
		}
	}

	m_prevValid = true;
	m_prevUser  = m_user;
	m_prevEnd   = m_last;

	return removeNode;
}

bool CLoopDetect::check(const std::string& user, const std::string& node)
{
	TimePoint now = steady_clock::now();

	// Check both, so each logs its own expiry
	bool userBlocked = isBlocked(callsignBase(user), now);
	bool nodeBlocked = isBlocked(callsignBase(node), now);

	return userBlocked || nodeBlocked;
}

bool CLoopDetect::checkLink(const std::string& node)
{
	std::map<std::string, CPenalty>::iterator it = m_penalties.find(callsignBase(node));
	if (it == m_penalties.end() || !it->second.m_linkBlocked)
		return false;

	if (steady_clock::now() < it->second.m_blockUntil)
		return true;

	it->second.m_linkBlocked = false;

	return false;
}

void CLoopDetect::clock(unsigned int ms)
{
	m_purgeTimer.clock(ms);
	if (m_purgeTimer.hasExpired()) {
		TimePoint now = steady_clock::now();

		for (std::map<std::string, CPenalty>::iterator it = m_penalties.begin(); it != m_penalties.end();) {
			const CPenalty& p = it->second;

			bool blockExpired   = now >= p.m_blockUntil;
			bool strikesDecayed = p.m_strikes == 0U || now - p.m_lastStrike > seconds(LOOP_STRIKE_DECAY_SEC);

			// A link block ends with the TX block
			if (blockExpired && strikesDecayed)
				it = m_penalties.erase(it);
			else
				++it;
		}

		m_purgeTimer.start();
	}
}

bool CLoopDetect::isBlocked(const std::string& key, const TimePoint& now)
{
	if (key.empty())
		return false;

	std::map<std::string, CPenalty>::iterator it = m_penalties.find(key);
	if (it == m_penalties.end())
		return false;

	CPenalty& p = it->second;

	if (now < p.m_blockUntil) {
		// Rate limited, a sustained loop would flood the log
		if (!p.m_dropLogged || now - p.m_lastDropLog >= seconds(LOOP_DROP_LOG_SEC)) {
			long long left = duration_cast<seconds>(p.m_blockUntil - now).count();
			LogMessage("Loop block: dropping transmission from %s (block expires in %llds)", key.c_str(), left);
			p.m_lastDropLog = now;
			p.m_dropLogged  = true;
		}

		return true;
	}

	if (p.m_expiryLog) {
		LogMessage("Loop detection: TX block expired for %s", key.c_str());
		p.m_expiryLog = false;
	}

	return false;
}
