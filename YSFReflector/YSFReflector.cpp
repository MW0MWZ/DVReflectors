/*
*   Copyright (C) 2016,2018,2020,2021 by Jonathan Naylor G4KLX
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

#include "YSFReflector.h"
#include "BlockList.h"
#include "LoopDetect.h"
#include "StopWatch.h"
#include "Network.h"
#include "Version.h"
#include "Thread.h"
#include "Log.h"
#include "GitVersion.h"

#if defined(_WIN32) || defined(_WIN64)
#include <Windows.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <pwd.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
const char* DEFAULT_INI_FILE = "YSFReflector.ini";
#else
const char* DEFAULT_INI_FILE = "/etc/YSFReflector.ini";
#endif

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <ctime>
#include <cstring>
#include <string>
#include <unordered_set>

// Loop detection user: the source callsign, or the node's until the source is known
static std::string ysfUser(const unsigned char* src, const unsigned char* tag)
{
	if (::memcmp(src, "??????????", YSF_CALLSIGN_LENGTH) == 0)
		return std::string((char*)tag, YSF_CALLSIGN_LENGTH);

	return std::string((char*)src, YSF_CALLSIGN_LENGTH);
}

int main(int argc, char** argv)
{
	const char* iniFile = DEFAULT_INI_FILE;
	if (argc > 1) {
		for (int currentArg = 1; currentArg < argc; ++currentArg) {
			std::string arg = argv[currentArg];
			if ((arg == "-v") || (arg == "--version")) {
				::fprintf(stdout, "YSFReflector version %s git #%.7s\n", VERSION, gitversion);
				return 0;
			} else if (arg.substr(0, 1) == "-") {
				::fprintf(stderr, "Usage: YSFReflector [-v|--version] [filename]\n");
				return 1;
			} else {
				iniFile = argv[currentArg];
			}
		}
	}

	CYSFReflector* reflector = new CYSFReflector(std::string(iniFile));
	reflector->run();
	delete reflector;

	return 0;
}

CYSFReflector::CYSFReflector(const std::string& file) :
m_conf(file),
m_repeaters()
{
	CUDPSocket::startup();
}

CYSFReflector::~CYSFReflector()
{
	CUDPSocket::shutdown();
}

void CYSFReflector::run()
{
	bool ret = m_conf.read();
	if (!ret) {
		::fprintf(stderr, "YSFReflector: cannot read the .ini file\n");
		return;
	}

#if !defined(_WIN32) && !defined(_WIN64)
	bool m_daemon = m_conf.getDaemon();
	if (m_daemon) {
		// Create new process
		pid_t pid = ::fork();
		if (pid == -1) {
			::fprintf(stderr, "Couldn't fork() , exiting\n");
			return;
		} else if (pid != 0) {
			exit(EXIT_SUCCESS);
		}

		// Create new session and process group
		if (::setsid() == -1) {
			::fprintf(stderr, "Couldn't setsid(), exiting\n");
			return;
		}

		// Set the working directory to the root directory
		if (::chdir("/") == -1) {
			::fprintf(stderr, "Couldn't cd /, exiting\n");
			return;
		}

		// If we are currently root...
		if (getuid() == 0) {
			struct passwd* user = ::getpwnam("mmdvm");
			if (user == NULL) {
				::fprintf(stderr, "Could not get the mmdvm user, exiting\n");
				return;
			}

			uid_t mmdvm_uid = user->pw_uid;
			gid_t mmdvm_gid = user->pw_gid;

			// Set user and group ID's to mmdvm:mmdvm
			if (setgid(mmdvm_gid) != 0) {
				::fprintf(stderr, "Could not set mmdvm GID, exiting\n");
				return;
			}

			if (setuid(mmdvm_uid) != 0) {
				::fprintf(stderr, "Could not set mmdvm UID, exiting\n");
				return;
			}

			// Double check it worked (AKA Paranoia) 
			if (setuid(0) != -1) {
				::fprintf(stderr, "It's possible to regain root - something is wrong!, exiting\n");
				return;
			}
		}
	}
#endif

#if !defined(_WIN32) && !defined(_WIN64)
        ret = ::LogInitialise(m_daemon, m_conf.getLogFilePath(), m_conf.getLogFileRoot(), m_conf.getLogFileLevel(), m_conf.getLogDisplayLevel(), m_conf.getLogFileRotate());
#else
        ret = ::LogInitialise(false, m_conf.getLogFilePath(), m_conf.getLogFileRoot(), m_conf.getLogFileLevel(), m_conf.getLogDisplayLevel(), m_conf.getLogFileRotate());
#endif
	if (!ret) {
		::fprintf(stderr, "YSFReflector: unable to open the log file\n");
		return;
	}

#if !defined(_WIN32) && !defined(_WIN64)
	if (m_daemon) {
		::close(STDIN_FILENO);
		::close(STDOUT_FILENO);
		::close(STDERR_FILENO);
	}
#endif

	CNetwork network(m_conf.getNetworkPort(), m_conf.getId(), m_conf.getName(), m_conf.getDescription(), m_conf.getNetworkDebug());

	ret = network.open();
	if (!ret) {
		::LogFinalise();
		return;
	}

	CBlockList blockList(m_conf.getBlockListFile(), m_conf.getBlockListTime());
	blockList.start();

	CLoopDetect loopDetect;

	// Address of the node of the transmission being scored, strike 3 removes it
	sockaddr_storage loopAddr;
	::memset(&loopAddr, 0x00U, sizeof(sockaddr_storage));

	network.setCount(0);
	
	CStopWatch stopWatch;
	stopWatch.start();

	CTimer dumpTimer(1000U, 120U);
	dumpTimer.start();

	CTimer pollTimer(1000U, 5U);
	pollTimer.start();

	LogMessage("YSFReflector-%s is starting", VERSION);
	LogMessage("Built %s %s (GitID #%.7s)", __TIME__, __DATE__, gitversion);

	CTimer watchdogTimer(1000U, 0U, 1500U);

	unsigned char tag[YSF_CALLSIGN_LENGTH];
	unsigned char src[YSF_CALLSIGN_LENGTH];
	unsigned char dst[YSF_CALLSIGN_LENGTH];

	bool blocked = false;

	// Last blocked transmission, so it is only logged once
	unsigned char blockedTag[YSF_CALLSIGN_LENGTH];
	unsigned char blockedSrc[YSF_CALLSIGN_LENGTH];
	CTimer blockedTimer(1000U, 0U, 1500U);

	// Blocked nodes already logged, stops their polls flooding the log
	std::unordered_set<std::string> blockedNodes;

	for (;;) {
		unsigned char buffer[200U];
		sockaddr_storage addr;
		unsigned int addrLen;

		unsigned int len = network.readData(buffer, 200U, addr, addrLen);
		if (len > 0U) {
			CYSFRepeater* rpt = findRepeater(addr);
			// Refuse to link a blocked node, or one barred for looping
			if (::memcmp(buffer, "YSFP", 4U) == 0 && rpt == NULL && (blockList.check(buffer + 4U) || loopDetect.checkLink(std::string((char*)(buffer + 4U), 10U)))) {
				char buff[80U];
				CUDPSocket::display(addr, buff, 80U);
				if (blockedNodes.insert(std::string(buff)).second)
					LogMessage("Linking of %10.10s (%s) blocked", buffer + 4U, buff);
			} else if (::memcmp(buffer, "YSFP", 4U) == 0) {
				if (rpt == NULL) {
					rpt = new CYSFRepeater;
					rpt->m_callsign = std::string((char*)(buffer + 4U), 10U);
					::memcpy(&rpt->m_addr, &addr, sizeof(struct sockaddr_storage));
					rpt->m_addrLen  = addrLen;
					m_repeaters.push_back(rpt);
					network.setCount(m_repeaters.size());

					char buff[80U];
					LogMessage("Adding %s (%s)", rpt->m_callsign.c_str(), CUDPSocket::display(addr, buff, 80U));
					blockedNodes.erase(std::string(buff));
				}
				rpt->m_timer.start();
				network.writePoll(addr, addrLen);
			} else if (::memcmp(buffer + 0U, "YSFU", 4U) == 0 && rpt != NULL) {
				char buff[80U];
				LogMessage("Removing %s (%s) unlinked", rpt->m_callsign.c_str(), CUDPSocket::display(addr, buff, 80U));

				// Cut short by the unlink, not scored
				if (CUDPSocket::match(loopAddr, rpt->m_addr))
					loopDetect.cancel();

				for (std::vector<CYSFRepeater*>::iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
					if (CUDPSocket::match((*it)->m_addr, rpt->m_addr)) {
						delete *it;
						m_repeaters.erase(it);
						break;
					}
				}
				network.setCount(m_repeaters.size());
			} else if (::memcmp(buffer + 0U, "YSFD", 4U) == 0 && rpt != NULL) {
				if (!watchdogTimer.isRunning()) {
					::memcpy(tag, buffer + 4U, YSF_CALLSIGN_LENGTH);

					if (::memcmp(buffer + 14U, "          ", YSF_CALLSIGN_LENGTH) != 0)
						::memcpy(src, buffer + 14U, YSF_CALLSIGN_LENGTH);
					else
						::memcpy(src, "??????????", YSF_CALLSIGN_LENGTH);

					if (::memcmp(buffer + 24U, "          ", YSF_CALLSIGN_LENGTH) != 0)
						::memcpy(dst, buffer + 24U, YSF_CALLSIGN_LENGTH);
					else
						::memcpy(dst, "??????????", YSF_CALLSIGN_LENGTH);

					// Loop detection keys: the user (or the node until the user is known) and the linked node
					std::string user = ysfUser(src, tag);
					std::string node = rpt->m_callsign;

					// Block the user or the node they are on
					bool listed = blockList.check(src) || blockList.check(tag);
					blocked = listed || loopDetect.check(user, node);
					if (listed) {
						if (!blockedTimer.isRunning() || ::memcmp(tag, blockedTag, YSF_CALLSIGN_LENGTH) != 0 || ::memcmp(src, blockedSrc, YSF_CALLSIGN_LENGTH) != 0) {
							LogMessage("Data from %10.10s at %10.10s blocked", src, tag);
							::memcpy(blockedTag, tag, YSF_CALLSIGN_LENGTH);
							::memcpy(blockedSrc, src, YSF_CALLSIGN_LENGTH);
						}

						blockedTimer.start();

						if ((buffer[34U] & 0x01U) == 0x01U)
							blockedTimer.stop();
					} else if (!blocked) {
						LogMessage("Received data from %10.10s to %10.10s at %10.10s", src, dst, tag);
						loopDetect.start(user, node);
						::memcpy(&loopAddr, &addr, sizeof(sockaddr_storage));
					}
				} else {
					if (::memcmp(tag, buffer + 4U, YSF_CALLSIGN_LENGTH) == 0) {
						bool changed = false;

						if (::memcmp(buffer + 14U, "          ", YSF_CALLSIGN_LENGTH) != 0 && ::memcmp(src, "??????????", YSF_CALLSIGN_LENGTH) == 0) {
							::memcpy(src, buffer + 14U, YSF_CALLSIGN_LENGTH);
							changed = true;
						}

						if (::memcmp(buffer + 24U, "          ", YSF_CALLSIGN_LENGTH) != 0 && ::memcmp(dst, "??????????", YSF_CALLSIGN_LENGTH) == 0) {
							::memcpy(dst, buffer + 24U, YSF_CALLSIGN_LENGTH);
							changed = true;
						}

						if (changed) {
							std::string user = ysfUser(src, tag);
							loopDetect.setUser(user);

							// Block the user or the node they are on
							bool listed = blockList.check(src) || blockList.check(tag);
							blocked = listed || loopDetect.check(user, rpt->m_callsign);
							if (blocked) {
								// Blocked transmissions aren't scored, and the next packet is judged afresh
								loopDetect.cancel();
								watchdogTimer.stop();
								if (listed) {
									LogMessage("Data from %10.10s at %10.10s blocked", src, tag);

									// Logged, the rest of this transmission isn't
									::memcpy(blockedTag, tag, YSF_CALLSIGN_LENGTH);
									::memcpy(blockedSrc, src, YSF_CALLSIGN_LENGTH);
									blockedTimer.start();
								}
							} else {
								LogMessage("Received data from %10.10s to %10.10s at %10.10s", src, dst, tag);
							}
						}
					}
				}

				if (!blocked) {
					watchdogTimer.start();
					loopDetect.touch();

					for (std::vector<CYSFRepeater*>::const_iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
						if (!CUDPSocket::match((*it)->m_addr, addr))
							network.writeData(buffer, (*it)->m_addr, (*it)->m_addrLen);
					}

					if ((buffer[34U] & 0x01U) == 0x01U) {
						LogMessage("Received end of transmission");
						watchdogTimer.stop();

						// Strike 3 removes the node
						if (loopDetect.end() && removeRepeater(loopAddr, "loop detected"))
							network.setCount(m_repeaters.size());
					}
				}
			}
		}

		unsigned int ms = stopWatch.elapsed();
		stopWatch.start();

		pollTimer.clock(ms);
		if (pollTimer.hasExpired()) {
			for (std::vector<CYSFRepeater*>::const_iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it)
				network.writePoll((*it)->m_addr, (*it)->m_addrLen);
			pollTimer.start();
		}

		// Remove any repeaters that haven't reported for a while
		for (std::vector<CYSFRepeater*>::iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it)
			(*it)->m_timer.clock(ms);

		for (std::vector<CYSFRepeater*>::iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
			if ((*it)->m_timer.hasExpired()) {
				char buff[80U];
				LogMessage("Removing %s (%s) disappeared", (*it)->m_callsign.c_str(),
														   CUDPSocket::display((*it)->m_addr, buff, 80U));

				// Cut short by the timeout, not scored
				if (CUDPSocket::match(loopAddr, (*it)->m_addr))
					loopDetect.cancel();

				delete *it;
				m_repeaters.erase(it);
				network.setCount(m_repeaters.size());
				break;
			}
		}

		watchdogTimer.clock(ms);
		if (watchdogTimer.isRunning() && watchdogTimer.hasExpired()) {
			LogMessage("Network watchdog has expired");
			watchdogTimer.stop();

			// Strike 3 removes the node
			if (loopDetect.end() && removeRepeater(loopAddr, "loop detected"))
				network.setCount(m_repeaters.size());
		}

		loopDetect.clock(ms);

		blockedTimer.clock(ms);
		if (blockedTimer.isRunning() && blockedTimer.hasExpired())
			blockedTimer.stop();

		dumpTimer.clock(ms);
		if (dumpTimer.hasExpired()) {
			dumpRepeaters();
			dumpTimer.start();
		}

		if (blockList.clock(ms)) {
			blockedNodes.clear();

			// Drop linked nodes that are now blocked
			for (std::vector<CYSFRepeater*>::iterator it = m_repeaters.begin(); it != m_repeaters.end();) {
				if (blockList.check((const unsigned char*)(*it)->m_callsign.c_str())) {
					char buff[80U];
					LogMessage("Removing %s (%s) blocked", (*it)->m_callsign.c_str(), CUDPSocket::display((*it)->m_addr, buff, 80U));

					if (CUDPSocket::match(loopAddr, (*it)->m_addr))
						loopDetect.cancel();

					delete *it;
					it = m_repeaters.erase(it);
				} else {
					++it;
				}
			}

			network.setCount(m_repeaters.size());
		}

		if (ms < 5U)
			CThread::sleep(5U);
	}

	network.close();

	::LogFinalise();
}

bool CYSFReflector::removeRepeater(const sockaddr_storage& addr, const char* reason)
{
	for (std::vector<CYSFRepeater*>::iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
		if (CUDPSocket::match((*it)->m_addr, addr)) {
			char buff[80U];
			LogMessage("Removing %s (%s) %s", (*it)->m_callsign.c_str(), CUDPSocket::display((*it)->m_addr, buff, 80U), reason);

			delete *it;
			m_repeaters.erase(it);
			return true;
		}
	}

	return false;
}

CYSFRepeater* CYSFReflector::findRepeater(const sockaddr_storage& addr) const
{
	for (std::vector<CYSFRepeater*>::const_iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
		if (CUDPSocket::match(addr, (*it)->m_addr))
			return *it;
	}

	return NULL;
}

void CYSFReflector::dumpRepeaters() const
{
	if (m_repeaters.size() == 0U) {
		LogMessage("No repeaters/gateways linked");
		return;
	}

	LogMessage("Currently linked repeaters/gateways:");

	for (std::vector<CYSFRepeater*>::const_iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
		char buffer[80U];
		LogMessage("    %s: %s %u/%u", (*it)->m_callsign.c_str(),
									   CUDPSocket::display((*it)->m_addr, buffer, 80U),
									   (*it)->m_timer.getTimer(),
									   (*it)->m_timer.getTimeout());
	}
}
