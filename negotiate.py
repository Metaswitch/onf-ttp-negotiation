#!/usr/bin/env python
# Copyright (c) Metaswitch Networks 2012-2012. All rights reserved.

import logging
from pprint import pformat
import sys
import math

_log = logging.getLogger("neg")

def parse_version(ver):
    """
    Parses a dot-separated string version into a tuple.  Number are
    converted to ints, everything else is left as a string.
    
    TODO: Handle +/- separators for semver-style versions.
    
    >>> parse_version("1.2.3.beta")
    (1, 2, 3, 'beta')
    """
    parts = ver.split(".")
    for i in xrange(len(parts)):
        try:
            parts[i] = int(parts[i])
        except ValueError:
            # Pass strings through.
            pass
    return tuple(parts)

def format_version(ver_tuple):
    """
    Converts a version tuple into a string.
    
    >>> format_version((1, 2, 3, "beta"))
    '1.2.3.beta'
    """
    return ".".join([str(x) for x in ver_tuple])

class Switch(object):
    """
    Switch base class, handles initial protocol version negotiation and 
    provides methods to check parameters against constraints.
    """
    VERSIONS_SUPPORTED = ["1.0"]
    TTPS_SUPPORTED = []

    def on_ttp_begin(self, msg):
        """
        Handle TTP begin message, returns best match version.
        """
        # Calculate shared versions
        # TODO strip "too detailed" version info
        our_versions = {parse_version(v) for v in self.VERSIONS_SUPPORTED}
        their_versions = {parse_version(v) for v in msg["versions"]}
        _log.debug("Our versions %s, theirs %s", our_versions, their_versions)
        shared_versions = list(our_versions.intersection(their_versions))
        # Respond with highest shared version.
        shared_versions.sort(reverse=True)
        return "ttp_version_resp", {"version": format_version(shared_versions[0])}

    def on_list_ttps(self, msg):
        return "list_ttps_resp", {"ttps": self.TTPS_SUPPORTED}

    def handle_msg(self, msg_type, payload={}):
        _log.info("CONTROLLER -> SWITCH %s\n%s", msg_type, pformat(payload))
        try:
            method = getattr(self, "on_" + msg_type)
        except KeyError:
            _log.exception("Unknown message type %s" % msg_type)
            raise
        else:
            resp_type, response = method(payload)
            _log.info("SWITCH -> CONTROLLER %s\n%s", resp_type, pformat(response))
            return resp_type, response

    def constraints_met(self, constraints, params):
        _log.debug("Checking if %s meets %s", params, constraints)
        for cons in constraints:
            if cons["type"] in ("max", "min", "best"):
                val = params[cons["param"]]
                if "min" in cons and val < cons["min"]:
                    _log.debug("Min constraint violated: %s < %s", val, cons["min"])
                    return False
                if "max" in cons and val > cons["max"]:
                    _log.debug("Max constraint violated: %s > %s", val, cons["max"])
                    return False
            if cons["type"] == "ratio":
                v1 = params[cons["param1"]]
                v2 = params[cons["param2"]]
                ratio = v2 * 1.0 / v1
                if "min" in cons and ratio < cons["min"]:
                    _log.debug("Ratio constraint violated: %s < %s", ratio, cons["min"])
                    return False
                if "max" in cons and ratio > cons["max"]:
                    _log.debug("Ratio constraint violated: %s > %s", ratio, cons["max"])
                    return False
        _log.debug("Constraints met")
        return True

    def score(self, constraints, params):
        """
        Scores a set of parameters against the constraints, returns a
        greater number for parameters that are a better match for the
        constraints.
        """
        score = 0
        for cons in constraints:
            _log.debug("Scoring constraint %s", cons)
            if cons["type"] in ("max", "min", "best"):
                val = params[cons["param"]]
                if cons["type"] == "max": score += val * cons["score"]
                if cons["type"] == "min": score -= val * cons["score"]
                if cons["type"] == "best":
                    if isinstance(cons["value"], bool):
                        score += cons["score"] if val == cons["value"] else 0
                    else:
                        # Assume int
                        score += abs(val - cons["value"]) * cons["score"]
            elif cons["type"] == "ratio":
                v1 = params[cons["param1"]]
                v2 = params[cons["param2"]]
                ratio = v2 / v1
                score -= abs(ratio - cons["ratio"]) * cons["score"]

        _log.debug("Parameter score %s: %s", score, params)
        return score

class SimpleIPv4Switch(Switch):
    """
    A basic IPV4-only switch with only a few fixed parameter sets.
    """
    TTPS_SUPPORTED = [("org.opennetworking/ttps/IPV4", "2.0"),
                      ("org.opennetworking/ttps/IPV4", "1.0"),
                      ("com.metaswitch/ttps/PrivateSwitch", "2.0"), ]

    PARAM_SETS = {
        ("org.opennetworking/ttps/IPV4", "1.0"): [
            {
                # MAC-heavy
                "IPV4 table size": 1000,
                "MAC table size": 10000,
            },
            {
                # Balanced
                "IPV4 table size": 5000,
                "MAC table size": 5000,
            },
            {
                # IP Heavy
                "IPV4 table size": 10000,
                "MAC table size": 2000,
            },
        ],
        ("org.opennetworking/ttps/IPV4", "2.0"): [
            {
                # MAC-heavy
                "IPV4 table size": 1000,
                "MAC table size": 10000,
                "Feature X": True,
            },
            {
                # Balanced
                "IPV4 table size": 5000,
                "MAC table size": 5000,
                "Feature X": False,
            },
            {
                # Balanced with whizzy feature
                "IPV4 table size": 4000,
                "MAC table size": 4000,
                "Feature X": True,
            },
            {
                # IP Heavy
                "IPV4 table size": 10000,
                "MAC table size": 2000,
                "Feature X": True,
            },
        ]
    }

    def on_ttp_query(self, msg):
        # We only support a few parameter sets, filter the ones that meet the
        # absolute constraints.
        ttp = msg["ttp_name"], msg["ttp_version"]
        cons = msg["param_constraints"]
        available_params = [p for p in self.PARAM_SETS[ttp] if
                            self.constraints_met(cons, p)]
        # Score them to find the best remaining.
        scored_params = [(self.score(cons, p), p) for p in available_params]
        scored_params.sort(reverse=True)
        try:
            return "ttp_query_resp", {"params": scored_params[0][1]}
        except IndexError:
            return "ttp_query_resp_err", {"error": "No match"}

class VariableIPv4Switch(Switch):
    """
    An IPv4 switch that has a continuous tradeoff between MAC entries
    and IPv4 entries.
    """
    TTPS_SUPPORTED = [("org.opennetworking/ttps/IPV4", "1.0")]

    def apply_constraints(self, constraints, params):
        """
        Makes safe adjustments to params to meet the constraints.  e.g.
        reduces values in params to the maxima specified in constraints.
        """
        for cons in constraints:
            if cons["type"] in ("max", "min", "best"):
                param = cons["param"]
                if "max" in cons:
                    # We can always do fewer
                    params[param] = min(cons["max"], params[param])
                if cons["type"] == "best" and cons["value"] < params[param]:
                    # We can always do fewer
                    params[param] = cons["value"]
            elif cons["type"] == "ratio":
                v1 = params[cons["param1"]]
                v2 = params[cons["param2"]]
                if "max" in cons:
                    max_v2 = v1 / cons["max"]
                    params[cons["param2"]] = min(v2, max_v2)
                if "min" in cons:
                    max_v1 = v2 * cons["max"]
                    params[cons["param1"]] = min(v1, max_v1)

    def on_ttp_query(self, msg):
        # Assume we have 10,000 memory slots.
        best_params = None
        best_score = None
        cons = msg["param_constraints"]

        # We can use domain-specific knowledge to write a simple ad-hoc
        # algorithm rather than needing a full constraint solver.
        for num_macs in xrange(0, 10000, 100):
            num_ips = 10000 - num_macs
            params = {
                "IPV4 table size": num_ips,
                "MAC table size": num_macs,
            }
            _log.debug("Params: %s", params)
            self.apply_constraints(cons, params)
            if self.constraints_met(cons, params):
                score = self.score(cons, params)
                _log.debug("Score %s %s", score, params)
                if best_score is None or score > best_score:
                    best_score = score
                    best_params = params
                    _log.debug("New best %s %s", score, params)

        return "ttp_query_resp", {"params": best_params}

class OFCP(object):
    """
    OFCP, negotiates with a switch to agreea  parameter set.
    """
    PREFERRED_TTPS = [("org.opennetworking/ttps/IPV4+IPV6", "2.0"),
                      ("org.opennetworking/ttps/IPV4", "2.0"),
                      ("org.opennetworking/ttps/IPV4", "1.0"),
                      ("org.opennetworking/ttps/IPV6", "1.0")]

    def negotiate_with(self, switch):
        # (1) Negotiate the version of the negotiation protocol itself.
        _log.info("Negotiating with %s", switch.__class__.__name__)
        _, resp = switch.handle_msg("ttp_begin", {"versions": ["1.0", "2.0"]})
        _log.info("Using negotiation protocol version %s", resp["version"])
        # TODO Handle different versions differently!

        # (2) Request TTP list. Find best match.   (Note: a more complex
        # controller could investigate multiple TTPs.)
        _log.info("Requesting TTP list.")
        _, resp = switch.handle_msg("list_ttps")
        preferred_ttp = None
        for ttp in self.PREFERRED_TTPS:
            if ttp in resp["ttps"]:
                _log.info("Preferred TTP is %s", ttp)
                preferred_ttp = ttp
                break
        if preferred_ttp is None:
            _log.error("Negotiation failed, no shared TTPs")
            return

        # (3) Specific negotiation for each TTP type.
        ttp_name, ttp_version = preferred_ttp
        if "IPV4+IPV6" in ttp_name: self.negotiate_ipv4_and_ipv6(switch, ttp_name, ttp_version)
        elif "IPV4" in ttp_name: self.negotiate_ipv4(switch, ttp_name, ttp_version)
        elif "IPV6" in ttp_name: self.negotiate_ipv6(switch, ttp_name, ttp_version)

        # (4) TODO Actually select the winner

    def negotiate_ipv4(self, switch, ttp_name, ttp_version):
        _log.debug("Negotiating for %s @ %s", ttp_name, ttp_version)
        negotiation_msg = {
            "ttp_name": ttp_name,
            "ttp_version": ttp_version,
            "param_constraints": [
                {"type": "max",
                 "param": "IPV4 table size",
                 "min": 3000,
                 "max": 10000,
                 "score": 11, },
                {"type": "best",
                 "param": "MAC table size",
                 "value": 6000,
                 "min": 3000,
                 "max": 7000,
                 "score": 10, },
                {"type": "ratio",
                 "param1": "IPV4 table size",
                 "param2": "MAC table size",
                 "min": 0.8,
                 "ratio": 1.1,
                 "max": 1.2,
                 "score": 9000},
            ]
        }

        if ttp_version == "2.0":
            # Maybe 2.0 added a new parameter that we care about?
            _log.debug("Using v2.0")
            negotiation_msg["param_constraints"].append({
                "param": "Feature X",
                "type": "best",
                "value": True,
                "score": 1001,  # Worth 1001 IP entries
            })

        switch.handle_msg("ttp_query", negotiation_msg)

    def negotiate_ipv6(self, switch, ttp_name, ttp_version):
        # TODO
        raise NotImplementedError()

    def negotiate_ipv4_and_ipv6(self, switch, ttp_name, ttp_version):
        # TODO
        raise NotImplementedError()

def main():
    ofcp = OFCP()

    _log.critical("****************************************")
    _log.critical("****** Scenario (1) simple switch ******")
    _log.critical("****************************************")
    ipv4_switch = SimpleIPv4Switch()
    ofcp.negotiate_with(ipv4_switch)

    _log.critical("******************************************")
    _log.critical("****** Scenario (2) variable switch ******")
    _log.critical("******************************************")
    ipv4_switch = VariableIPv4Switch()
    ofcp.negotiate_with(ipv4_switch)


if __name__ == '__main__':
    logging.basicConfig(format="[%(levelname)s] %(message)s",
                        level=logging.DEBUG if "--debug" in sys.argv else logging.INFO)
    if "--test" in sys.argv:
        import doctest
        doctest.testmod()
    else:
        main()
