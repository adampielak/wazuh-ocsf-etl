#!/usr/bin/env python3
"""Writes both Grafana dashboard JSON files."""
import json, os

BASE = os.path.dirname(os.path.abspath(__file__))

# ─── helpers ────────────────────────────────────────────────────────────────

def ds():
    return {"type": "grafana-clickhouse-datasource", "uid": "${DS_CLICKHOUSE}"}

def target(sql, fmt=1, ref="A"):
    return {"datasource": ds(), "rawSql": sql, "format": fmt, "refId": ref}

def stat_panel(pid, title, sql, color, gx, gy, gw=3, gh=4, graph_mode="area"):
    return {
        "id": pid, "type": "stat", "title": title, "datasource": ds(),
        "gridPos": {"x": gx, "y": gy, "w": gw, "h": gh},
        "options": {
            "reduceOptions": {"values": False, "calcs": ["lastNotNull"], "fields": ""},
            "orientation": "auto", "textMode": "auto", "colorMode": "background",
            "graphMode": graph_mode, "justifyMode": "auto"
        },
        "fieldConfig": {
            "defaults": {"color": {"mode": "fixed", "fixedColor": color}, "unit": "short",
                "thresholds": {"mode": "absolute", "steps": [{"color": color, "value": None}]}},
            "overrides": []
        },
        "targets": [target(sql)]
    }

def row_panel(pid, title, y):
    return {"id": pid, "type": "row", "title": title, "collapsed": False,
            "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": []}

def level_override():
    return {"matcher": {"id": "byName", "options": "Level"}, "properties": [
        {"id": "custom.width", "value": 65},
        {"id": "thresholds", "value": {"mode": "absolute", "steps": [
            {"color": "green", "value": None}, {"color": "yellow", "value": 7},
            {"color": "orange", "value": 10},  {"color": "dark-red", "value": 13}]}},
        {"id": "custom.displayMode", "value": "color-background"}
    ]}

def max_level_override(col="Max Level"):
    return {"matcher": {"id": "byName", "options": col}, "properties": [
        {"id": "custom.width", "value": 85},
        {"id": "thresholds", "value": {"mode": "absolute", "steps": [
            {"color": "green", "value": None}, {"color": "yellow", "value": 7},
            {"color": "orange", "value": 10},  {"color": "dark-red", "value": 13}]}},
        {"id": "custom.displayMode", "value": "color-background"}
    ]}

def gauge_override(col, color):
    return {"matcher": {"id": "byName", "options": col}, "properties": [
        {"id": "custom.displayMode", "value": "lcd-gauge"},
        {"id": "color", "value": {"mode": "fixed", "fixedColor": color}}
    ]}

# ═══════════════════════════════════════════════════════════════════════════════
#  DASHBOARD 1 — Wazuh OCSF SOC
# ═══════════════════════════════════════════════════════════════════════════════

MERGE = "merge('wazuh_ocsf', '^ocsf_.+$')"
FILTERS = "device_name IN (${device_name:singlequote}) AND severity IN (${severity:singlequote}) AND class_name IN (${class_name:singlequote}) AND wazuh_rule_level >= ${min_level}"
AGENT_FILTER = "device_name IN (${device_name:singlequote}) AND wazuh_rule_level >= ${min_level}"
TIME = "$__timeFilter(time)"

def soc_panels():
    p = []

    # ── ROW: OVERVIEW ───────────────────────────────────────────────────────
    p.append(row_panel(1000, "── OVERVIEW ──", 0))

    p.append(stat_panel(1,  "Total Events",         f"SELECT count() AS \"Total Events\" FROM {MERGE} WHERE {TIME} AND {FILTERS}", "blue",     0,  1))
    p.append(stat_panel(2,  "Critical (≥13)",        f"SELECT count() AS \"Critical\" FROM {MERGE} WHERE {TIME} AND wazuh_rule_level >= 13 AND device_name IN (${{device_name:singlequote}})", "dark-red", 3,  1))
    p.append(stat_panel(3,  "High (10-12)",           f"SELECT count() AS \"High\" FROM {MERGE} WHERE {TIME} AND wazuh_rule_level BETWEEN 10 AND 12 AND device_name IN (${{device_name:singlequote}})", "orange",   6,  1))
    p.append(stat_panel(4,  "Medium (7-9)",           f"SELECT count() AS \"Medium\" FROM {MERGE} WHERE {TIME} AND wazuh_rule_level BETWEEN 7 AND 9 AND device_name IN (${{device_name:singlequote}})", "yellow",   9,  1))
    p.append(stat_panel(5,  "Unique Agents",          f"SELECT uniq(device_name) AS \"Agents\" FROM {MERGE} WHERE {TIME}", "teal",     12, 1, graph_mode="none"))
    p.append(stat_panel(6,  "Unique Rules Fired",     f"SELECT uniq(finding_uid) AS \"Rules\" FROM {MERGE} WHERE {TIME} AND {AGENT_FILTER}", "purple",   15, 1, graph_mode="none"))

    # Max Level — threshold colors
    p.append({
        "id": 7, "type": "stat", "title": "Max Rule Level", "datasource": ds(),
        "gridPos": {"x": 18, "y": 1, "w": 3, "h": 4},
        "options": {"reduceOptions": {"values": False, "calcs": ["lastNotNull"], "fields": ""},
                    "orientation": "auto", "textMode": "auto", "colorMode": "background",
                    "graphMode": "none", "justifyMode": "auto"},
        "fieldConfig": {
            "defaults": {"color": {"mode": "thresholds"}, "unit": "short",
                "thresholds": {"mode": "absolute", "steps": [
                    {"color": "green", "value": None}, {"color": "yellow", "value": 7},
                    {"color": "orange", "value": 10}, {"color": "dark-red", "value": 13}]}},
            "overrides": []
        },
        "targets": [target(f"SELECT max(wazuh_rule_level) AS \"Max Level\" FROM {MERGE} WHERE {TIME} AND device_name IN (${{device_name:singlequote}})")]
    })

    p.append(stat_panel(8, "MITRE Techniques Seen", f"SELECT uniq(attack_id) AS \"MITRE\" FROM {MERGE} WHERE {TIME} AND attack_id != '' AND device_name IN (${{device_name:singlequote}})", "dark-red", 21, 1, graph_mode="none"))

    # Alert volume timeseries
    p.append({
        "id": 9, "type": "timeseries", "title": "Alert Volume Over Time by Severity Level",
        "datasource": ds(), "gridPos": {"x": 0, "y": 5, "w": 18, "h": 8},
        "options": {"tooltip": {"mode": "multi", "sort": "desc"},
                    "legend": {"displayMode": "table", "placement": "bottom", "showLegend": True, "calcs": ["sum","max","mean"]}},
        "fieldConfig": {
            "defaults": {"custom": {"lineWidth": 2, "fillOpacity": 10, "gradientMode": "opacity", "spanNulls": False}},
            "overrides": [
                {"matcher": {"id": "byName", "options": "Critical"},      "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "dark-red"}}]},
                {"matcher": {"id": "byName", "options": "High"},          "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "orange"}}]},
                {"matcher": {"id": "byName", "options": "Medium"},        "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "yellow"}}]},
                {"matcher": {"id": "byName", "options": "Low"},           "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}]},
                {"matcher": {"id": "byName", "options": "Informational"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}}]}
            ]
        },
        "targets": [target(
            f"SELECT toStartOfInterval(time, INTERVAL $__interval_s SECOND) AS time,"
            f" countIf(wazuh_rule_level>=13) AS \"Critical\","
            f" countIf(wazuh_rule_level BETWEEN 10 AND 12) AS \"High\","
            f" countIf(wazuh_rule_level BETWEEN 7 AND 9) AS \"Medium\","
            f" countIf(wazuh_rule_level BETWEEN 4 AND 6) AS \"Low\","
            f" countIf(wazuh_rule_level < 4) AS \"Informational\""
            f" FROM {MERGE} WHERE {TIME} AND device_name IN (${{device_name:singlequote}})"
            f" AND class_name IN (${{class_name:singlequote}}) AND wazuh_rule_level >= ${{min_level}}"
            f" GROUP BY time ORDER BY time ASC", fmt=3)]
    })

    # Severity donut
    p.append({
        "id": 10, "type": "piechart", "title": "Severity Distribution",
        "datasource": ds(), "gridPos": {"x": 18, "y": 5, "w": 6, "h": 8},
        "options": {"pieType": "donut",
                    "tooltip": {"mode": "multi", "sort": "desc"},
                    "legend": {"displayMode": "table", "placement": "right", "showLegend": True, "values": ["value","percent"]},
                    "displayLabels": ["percent"]},
        "fieldConfig": {"defaults": {}, "overrides": [
            {"matcher": {"id": "byName", "options": "Critical"},      "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "dark-red"}}]},
            {"matcher": {"id": "byName", "options": "High"},          "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "orange"}}]},
            {"matcher": {"id": "byName", "options": "Medium"},        "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "yellow"}}]},
            {"matcher": {"id": "byName", "options": "Low"},           "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}]},
            {"matcher": {"id": "byName", "options": "Informational"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}}]}
        ]},
        "targets": [target(
            f"SELECT multiIf(wazuh_rule_level>=13,'Critical',wazuh_rule_level>=10,'High',"
            f"wazuh_rule_level>=7,'Medium',wazuh_rule_level>=4,'Low','Informational') AS \"Severity\","
            f" count() AS \"Events\" FROM {MERGE} WHERE {TIME} AND device_name IN (${{device_name:singlequote}})"
            f" AND wazuh_rule_level >= ${{min_level}} GROUP BY Severity ORDER BY Events DESC")]
    })

    # OCSF class pie
    p.append({
        "id": 11, "type": "piechart", "title": "OCSF Event Class Distribution",
        "datasource": ds(), "gridPos": {"x": 0, "y": 13, "w": 8, "h": 8},
        "options": {"pieType": "pie",
                    "tooltip": {"mode": "multi", "sort": "desc"},
                    "legend": {"displayMode": "table", "placement": "right", "showLegend": True, "values": ["value","percent"]},
                    "displayLabels": ["name"]},
        "fieldConfig": {"defaults": {}, "overrides": []},
        "targets": [target(
            f"SELECT class_name AS \"Class\", count() AS \"Events\" FROM {MERGE}"
            f" WHERE {TIME} AND {AGENT_FILTER}"
            f" GROUP BY class_name ORDER BY Events DESC")]
    })

    # Top agents bar
    p.append({
        "id": 12, "type": "barchart", "title": "Top 10 Agents by Alert Volume",
        "datasource": ds(), "gridPos": {"x": 8, "y": 13, "w": 8, "h": 8},
        "options": {"orientation": "horizontal", "barRadius": 0.05, "barWidth": 0.7,
                    "stacking": "none", "showValue": "auto", "fillOpacity": 75,
                    "tooltip": {"mode": "single"},
                    "legend": {"displayMode": "list", "placement": "bottom", "showLegend": False}},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "unit": "short"}, "overrides": []},
        "targets": [target(
            f"SELECT device_name AS \"Agent\", count() AS \"Events\" FROM {MERGE}"
            f" WHERE {TIME} AND wazuh_rule_level >= ${{min_level}}"
            f" GROUP BY device_name ORDER BY Events DESC LIMIT 10")]
    })

    # Top tactics bar
    p.append({
        "id": 13, "type": "barchart", "title": "Top MITRE Tactics",
        "datasource": ds(), "gridPos": {"x": 16, "y": 13, "w": 8, "h": 8},
        "options": {"orientation": "horizontal", "barRadius": 0.05, "barWidth": 0.7,
                    "stacking": "none", "showValue": "auto", "fillOpacity": 75,
                    "tooltip": {"mode": "single"},
                    "legend": {"displayMode": "list", "placement": "bottom", "showLegend": False}},
        "fieldConfig": {"defaults": {"color": {"mode": "fixed", "fixedColor": "dark-red"}, "unit": "short"}, "overrides": []},
        "targets": [target(
            f"SELECT attack_tactic AS \"Tactic\", count() AS \"Events\" FROM {MERGE}"
            f" WHERE {TIME} AND attack_tactic != '' AND device_name IN (${{device_name:singlequote}})"
            f" GROUP BY attack_tactic ORDER BY Events DESC LIMIT 12")]
    })

    # Top rules short table
    p.append({
        "id": 14, "type": "table", "title": "Top 10 Rules Firing Now",
        "datasource": ds(), "gridPos": {"x": 0, "y": 21, "w": 12, "h": 8},
        "options": {"footer": {"show": False}, "showHeader": True, "sortBy": [{"displayName": "Hits", "desc": True}]},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": [max_level_override("Level"),
                                      {"matcher": {"id": "byName", "options": "Hits"},   "properties": [{"id": "custom.width", "value": 70}]},
                                      {"matcher": {"id": "byName", "options": "Agents"}, "properties": [{"id": "custom.width", "value": 65}]}]},
        "targets": [target(
            f"SELECT finding_uid AS \"Rule ID\", finding_title AS \"Description\","
            f" max(wazuh_rule_level) AS \"Level\", count() AS \"Hits\", uniq(device_name) AS \"Agents\""
            f" FROM {MERGE} WHERE {TIME} AND {AGENT_FILTER}"
            f" GROUP BY finding_uid, finding_title ORDER BY Hits DESC LIMIT 10")]
    })

    # Top src IPs
    p.append({
        "id": 15, "type": "table", "title": "Top Source IPs",
        "datasource": ds(), "gridPos": {"x": 12, "y": 21, "w": 6, "h": 8},
        "options": {"footer": {"show": False}, "showHeader": True},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": [gauge_override("Events", "red")]},
        "targets": [target(
            f"SELECT src_ip AS \"Source IP\", count() AS \"Events\","
            f" uniq(device_name) AS \"Targets\", max(wazuh_rule_level) AS \"Max Lvl\""
            f" FROM {MERGE} WHERE {TIME} AND src_ip != '' AND {AGENT_FILTER}"
            f" GROUP BY src_ip ORDER BY Events DESC LIMIT 15")]
    })

    # Top users
    p.append({
        "id": 16, "type": "table", "title": "Top Users / Actors",
        "datasource": ds(), "gridPos": {"x": 18, "y": 21, "w": 6, "h": 8},
        "options": {"footer": {"show": False}, "showHeader": True},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": [gauge_override("Events", "purple")]},
        "targets": [target(
            f"SELECT actor_user AS \"User\", count() AS \"Events\","
            f" uniq(device_name) AS \"Agents\", max(wazuh_rule_level) AS \"Max Lvl\""
            f" FROM {MERGE} WHERE {TIME} AND actor_user != '' AND {AGENT_FILTER}"
            f" GROUP BY actor_user ORDER BY Events DESC LIMIT 15")]
    })

    # ── ROW: AGENT VISIBILITY ────────────────────────────────────────────────
    p.append(row_panel(1001, "── AGENT VISIBILITY ──", 29))

    p.append({
        "id": 20, "type": "table", "title": "Agent Status & Summary",
        "datasource": ds(), "gridPos": {"x": 0, "y": 30, "w": 24, "h": 8},
        "options": {"footer": {"show": False}, "showHeader": True, "sortBy": [{"displayName": "Events", "desc": True}]},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": [
                            max_level_override(),
                            {"matcher": {"id": "byName", "options": "Last Seen"}, "properties": [
                                {"id": "unit", "value": "dateTimeFromNow"}, {"id": "custom.width", "value": 130}]},
                            gauge_override("Events", "blue")
                        ]},
        "targets": [target(
            f"SELECT device_name AS \"Agent\", manager_name AS \"Manager\","
            f" count() AS \"Events\", max(wazuh_rule_level) AS \"Max Level\","
            f" countIf(wazuh_rule_level>=13) AS \"Critical\","
            f" countIf(wazuh_rule_level BETWEEN 10 AND 12) AS \"High\","
            f" countIf(wazuh_rule_level BETWEEN 7 AND 9) AS \"Medium\","
            f" uniq(finding_uid) AS \"Unique Rules\", uniq(class_name) AS \"OCSF Classes\","
            f" uniq(attack_id) AS \"MITRE IDs\", max(time) AS \"Last Seen\""
            f" FROM {MERGE} WHERE {TIME} GROUP BY device_name, manager_name ORDER BY Events DESC")]
    })

    # Per-agent trend (top 10 agents dynamic)
    p.append({
        "id": 21, "type": "timeseries", "title": "Per-Agent Event Trend",
        "datasource": ds(), "gridPos": {"x": 0, "y": 38, "w": 16, "h": 8},
        "options": {"tooltip": {"mode": "multi", "sort": "desc"},
                    "legend": {"displayMode": "table", "placement": "right", "showLegend": True, "calcs": ["sum"]}},
        "fieldConfig": {"defaults": {"custom": {"lineWidth": 2, "fillOpacity": 5, "spanNulls": False}}, "overrides": []},
        "targets": [target(
            f"SELECT toStartOfInterval(time, INTERVAL $__interval_s SECOND) AS time,"
            f" device_name, count() AS events FROM {MERGE} WHERE {TIME}"
            f" AND device_name IN (SELECT device_name FROM {MERGE} WHERE {TIME}"
            f" GROUP BY device_name ORDER BY count() DESC LIMIT 10)"
            f" GROUP BY time, device_name ORDER BY time ASC", fmt=3)]
    })

    # Agent stacked severity bar
    p.append({
        "id": 22, "type": "barchart", "title": "Agent Alert Level Distribution",
        "datasource": ds(), "gridPos": {"x": 16, "y": 38, "w": 8, "h": 8},
        "options": {"orientation": "horizontal", "barRadius": 0.05, "barWidth": 0.6,
                    "stacking": "normal", "showValue": "auto", "fillOpacity": 75,
                    "tooltip": {"mode": "multi"},
                    "legend": {"displayMode": "list", "placement": "bottom", "showLegend": True}},
        "fieldConfig": {"defaults": {"unit": "short"}, "overrides": [
            {"matcher": {"id": "byName", "options": "Critical"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "dark-red"}}]},
            {"matcher": {"id": "byName", "options": "High"},     "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "orange"}}]},
            {"matcher": {"id": "byName", "options": "Medium"},   "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "yellow"}}]},
            {"matcher": {"id": "byName", "options": "Low"},      "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}]}
        ]},
        "targets": [target(
            f"SELECT device_name AS \"Agent\","
            f" countIf(wazuh_rule_level>=13) AS \"Critical\","
            f" countIf(wazuh_rule_level BETWEEN 10 AND 12) AS \"High\","
            f" countIf(wazuh_rule_level BETWEEN 7 AND 9) AS \"Medium\","
            f" countIf(wazuh_rule_level < 7) AS \"Low\""
            f" FROM {MERGE} WHERE {TIME} GROUP BY device_name"
            f" ORDER BY (Critical + High) DESC LIMIT 15")]
    })

    # ── ROW: RULE & THREAT HUNTING ───────────────────────────────────────────
    p.append(row_panel(1002, "── RULE & THREAT HUNTING ──", 46))

    p.append({
        "id": 30, "type": "table", "title": "Top Wazuh Rules — Full Detail",
        "description": "finding_uid=Rule ID | finding_types=rule groups | decoder_name=decoder",
        "datasource": ds(), "gridPos": {"x": 0, "y": 47, "w": 14, "h": 10},
        "options": {"footer": {"show": False}, "showHeader": True, "sortBy": [{"displayName": "Hits", "desc": True}]},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": [
                            max_level_override(),
                            {"matcher": {"id": "byName", "options": "Hits"},     "properties": [{"id": "custom.width", "value": 70}, {"id": "custom.displayMode", "value": "lcd-gauge"}]},
                            {"matcher": {"id": "byName", "options": "Last Seen"},"properties": [{"id": "unit", "value": "dateTimeFromNow"}, {"id": "custom.width", "value": 120}]}
                        ]},
        "targets": [target(
            f"SELECT finding_uid AS \"Rule ID\", finding_title AS \"Rule Description\","
            f" count() AS \"Hits\", max(wazuh_rule_level) AS \"Max Level\","
            f" uniq(device_name) AS \"Agents\", max(wazuh_fired_times) AS \"Max Fired\","
            f" decoder_name AS \"Decoder\", attack_tactic AS \"Tactic\", max(time) AS \"Last Seen\""
            f" FROM {MERGE} WHERE {TIME} AND {FILTERS}"
            f" GROUP BY finding_uid, finding_title, decoder_name, attack_tactic"
            f" ORDER BY Hits DESC LIMIT 30")]
    })

    p.append({
        "id": 31, "type": "timeseries", "title": "Rule Level Trend Over Time",
        "datasource": ds(), "gridPos": {"x": 14, "y": 47, "w": 10, "h": 10},
        "options": {"tooltip": {"mode": "multi", "sort": "desc"},
                    "legend": {"displayMode": "list", "placement": "bottom", "showLegend": True}},
        "fieldConfig": {"defaults": {"custom": {"lineWidth": 2, "fillOpacity": 8, "spanNulls": False}},
                        "overrides": [
                            {"matcher": {"id": "byName", "options": "Critical"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "dark-red"}}]},
                            {"matcher": {"id": "byName", "options": "High"},     "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "orange"}}]},
                            {"matcher": {"id": "byName", "options": "Medium"},   "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "yellow"}}]}
                        ]},
        "targets": [target(
            f"SELECT toStartOfInterval(time, INTERVAL $__interval_s SECOND) AS time,"
            f" countIf(wazuh_rule_level>=13) AS \"Critical\","
            f" countIf(wazuh_rule_level BETWEEN 10 AND 12) AS \"High\","
            f" countIf(wazuh_rule_level BETWEEN 7 AND 9) AS \"Medium\""
            f" FROM {MERGE} WHERE {TIME} AND device_name IN (${{device_name:singlequote}})"
            f" GROUP BY time ORDER BY time ASC", fmt=3)]
    })

    p.append({
        "id": 32, "type": "table", "title": "Rule Groups Breakdown",
        "datasource": ds(), "gridPos": {"x": 0, "y": 57, "w": 8, "h": 8},
        "options": {"footer": {"show": False}, "showHeader": True},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": [gauge_override("Events", "blue")]},
        "targets": [target(
            f"SELECT finding_types AS \"Rule Groups\", count() AS \"Events\","
            f" uniq(finding_uid) AS \"Rules\", max(wazuh_rule_level) AS \"Max Level\""
            f" FROM {MERGE} WHERE {TIME} AND finding_types != '' AND {AGENT_FILTER}"
            f" GROUP BY finding_types ORDER BY Events DESC LIMIT 20")]
    })

    p.append({
        "id": 33, "type": "table", "title": "Decoder Breakdown",
        "datasource": ds(), "gridPos": {"x": 8, "y": 57, "w": 8, "h": 8},
        "options": {"footer": {"show": False}, "showHeader": True},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": [gauge_override("Events", "teal")]},
        "targets": [target(
            f"SELECT decoder_name AS \"Decoder\", count() AS \"Events\","
            f" uniq(finding_uid) AS \"Rules\", uniq(device_name) AS \"Agents\""
            f" FROM {MERGE} WHERE {TIME} AND decoder_name != '' AND {AGENT_FILTER}"
            f" GROUP BY decoder_name ORDER BY Events DESC LIMIT 20")]
    })

    p.append({
        "id": 34, "type": "timeseries", "title": "Alerts per Minute",
        "datasource": ds(), "gridPos": {"x": 16, "y": 57, "w": 8, "h": 8},
        "options": {"tooltip": {"mode": "single"},
                    "legend": {"displayMode": "list", "placement": "bottom", "showLegend": False}},
        "fieldConfig": {"defaults": {"custom": {"lineWidth": 2, "fillOpacity": 20, "gradientMode": "opacity"}, "unit": "short"}, "overrides": []},
        "targets": [target(
            f"SELECT toStartOfMinute(time) AS time, count() AS \"Alerts/min\""
            f" FROM {MERGE} WHERE {TIME} AND {AGENT_FILTER}"
            f" GROUP BY time ORDER BY time ASC", fmt=3)]
    })

    # ── ROW: MITRE ATT&CK ────────────────────────────────────────────────────
    p.append(row_panel(1003, "── MITRE ATT&CK ──", 65))

    p.append({
        "id": 40, "type": "barchart", "title": "MITRE Tactics Coverage",
        "datasource": ds(), "gridPos": {"x": 0, "y": 66, "w": 10, "h": 9},
        "options": {"orientation": "horizontal", "barRadius": 0.05, "barWidth": 0.7,
                    "stacking": "none", "showValue": "auto", "fillOpacity": 75,
                    "tooltip": {"mode": "single"},
                    "legend": {"displayMode": "list", "placement": "bottom", "showLegend": False}},
        "fieldConfig": {"defaults": {"color": {"mode": "fixed", "fixedColor": "dark-red"}, "unit": "short"}, "overrides": []},
        "targets": [target(
            f"SELECT attack_tactic AS \"Tactic\", count() AS \"Events\""
            f" FROM {MERGE} WHERE {TIME} AND attack_tactic != ''"
            f" AND device_name IN (${{device_name:singlequote}})"
            f" GROUP BY attack_tactic ORDER BY Events DESC LIMIT 15")]
    })

    p.append({
        "id": 41, "type": "table", "title": "MITRE Techniques — Full Detail",
        "datasource": ds(), "gridPos": {"x": 10, "y": 66, "w": 14, "h": 9},
        "options": {"footer": {"show": False}, "showHeader": True, "sortBy": [{"displayName": "Hits", "desc": True}]},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": [
                            {"matcher": {"id": "byName", "options": "Technique ID"}, "properties": [
                                {"id": "custom.width", "value": 110},
                                {"id": "links", "value": [{"title": "MITRE ATT&CK", "url": "https://attack.mitre.org/techniques/${__value.raw}", "targetBlank": True}]}
                            ]},
                            gauge_override("Hits", "dark-red"),
                            max_level_override()
                        ]},
        "targets": [target(
            f"SELECT attack_id AS \"Technique ID\", attack_technique AS \"Technique\","
            f" attack_tactic AS \"Tactic\", count() AS \"Hits\","
            f" uniq(device_name) AS \"Agents\", max(wazuh_rule_level) AS \"Max Level\","
            f" uniq(finding_uid) AS \"Rules\""
            f" FROM {MERGE} WHERE {TIME} AND attack_id != ''"
            f" AND device_name IN (${{device_name:singlequote}})"
            f" GROUP BY attack_id, attack_technique, attack_tactic"
            f" ORDER BY Hits DESC LIMIT 25")]
    })

    p.append({
        "id": 42, "type": "timeseries", "title": "MITRE Tactic Trend Over Time",
        "datasource": ds(), "gridPos": {"x": 0, "y": 75, "w": 24, "h": 8},
        "options": {"tooltip": {"mode": "multi", "sort": "desc"},
                    "legend": {"displayMode": "table", "placement": "right", "showLegend": True, "calcs": ["sum"]}},
        "fieldConfig": {"defaults": {"custom": {"lineWidth": 2, "fillOpacity": 5, "spanNulls": False}}, "overrides": []},
        "targets": [target(
            f"SELECT toStartOfInterval(time, INTERVAL $__interval_s SECOND) AS time,"
            f" attack_tactic AS tactic, count() AS events"
            f" FROM {MERGE} WHERE {TIME} AND attack_tactic != ''"
            f" AND device_name IN (${{device_name:singlequote}})"
            f" GROUP BY time, tactic ORDER BY time ASC", fmt=3)]
    })

    # ── ROW: COMPLIANCE ──────────────────────────────────────────────────────
    p.append(row_panel(1004, "── COMPLIANCE ──", 83))

    for i, (cid, title, col_field, label, color, gx) in enumerate([
        (50, "PCI DSS Controls",  "pci_dss",    "PCI DSS",  "blue",   0),
        (51, "GDPR Articles",     "gdpr",        "GDPR",     "green",  4),
        (52, "HIPAA Sections",    "hipaa",       "HIPAA",    "orange", 8),
        (53, "NIST 800-53 Ctrls", "nist_800_53","NIST",     "purple", 12),
    ]):
        p.append(stat_panel(cid, title,
            f"SELECT uniq({col_field}) AS \"{label}\" FROM {MERGE} WHERE {TIME} AND {col_field} != '' AND device_name IN (${{device_name:singlequote}})",
            color, gx, 84, gw=6, gh=3, graph_mode="none"))

    compliance_defs = [
        (55, "PCI DSS",    "pci_dss",    "PCI DSS Req",   "blue",    0),
        (56, "GDPR",       "gdpr",       "GDPR Article",  "green",   6),
        (57, "HIPAA",      "hipaa",      "HIPAA Section", "orange",  12),
        (58, "NIST 800-53","nist_800_53","NIST Control",  "purple",  18),
    ]
    for cid, title, field, col_label, color, gx in compliance_defs:
        p.append({
            "id": cid, "type": "table", "title": title,
            "datasource": ds(), "gridPos": {"x": gx, "y": 87, "w": 6, "h": 9},
            "options": {"footer": {"show": False}, "showHeader": True},
            "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                            "overrides": [gauge_override("Events", color)]},
            "targets": [target(
                f"SELECT {field} AS \"{col_label}\", count() AS \"Events\","
                f" uniq(finding_uid) AS \"Rules\", uniq(device_name) AS \"Agents\""
                f" FROM {MERGE} WHERE {TIME} AND {field} != ''"
                f" AND device_name IN (${{device_name:singlequote}})"
                f" GROUP BY {field} ORDER BY Events DESC LIMIT 15")]
        })

    # ── ROW: NETWORK / FILE ──────────────────────────────────────────────────
    p.append(row_panel(1005, "── NETWORK / FILE / PROCESS EVENTS ──", 96))

    p.append({
        "id": 60, "type": "table", "title": "Top Network Connection Pairs",
        "datasource": ds(), "gridPos": {"x": 0, "y": 97, "w": 12, "h": 8},
        "options": {"footer": {"show": False}, "showHeader": True},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": [gauge_override("Connections", "blue")]},
        "targets": [target(
            f"SELECT src_ip AS \"Src IP\", dst_ip AS \"Dst IP\", dst_port AS \"Dst Port\","
            f" count() AS \"Connections\", uniq(device_name) AS \"Agents\""
            f" FROM {MERGE} WHERE {TIME} AND src_ip != '' AND dst_ip != ''"
            f" AND device_name IN (${{device_name:singlequote}})"
            f" GROUP BY src_ip, dst_ip, dst_port ORDER BY Connections DESC LIMIT 20")]
    })

    p.append({
        "id": 61, "type": "table", "title": "File Integrity Events",
        "datasource": ds(), "gridPos": {"x": 12, "y": 97, "w": 12, "h": 8},
        "options": {"footer": {"show": False}, "showHeader": True},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": [gauge_override("Events", "orange"), max_level_override("Level")]},
        "targets": [target(
            f"SELECT device_name AS \"Agent\", file_name AS \"File\","
            f" activity_name AS \"Action\","
            f" max(wazuh_rule_level) AS \"Level\", count() AS \"Events\""
            f" FROM {MERGE} WHERE {TIME} AND file_name != ''"
            f" AND device_name IN (${{device_name:singlequote}})"
            f" GROUP BY device_name, file_name, activity_name"
            f" ORDER BY Events DESC LIMIT 20")]
    })

    # ── ROW: LOG SOURCE VISIBILITY ───────────────────────────────────────────
    p.append(row_panel(1007, "── LOG SOURCE VISIBILITY ──", 105))

    p.append({
        "id": 80, "type": "table", "title": "Top Log Sources (src_location)",
        "description": "src_location = Wazuh log path/location. Shows which log files/sources are generating the most events.",
        "datasource": ds(), "gridPos": {"x": 0, "y": 106, "w": 8, "h": 9},
        "options": {"footer": {"show": False}, "showHeader": True},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": [gauge_override("Events", "blue"), max_level_override()]},
        "targets": [target(
            f"SELECT src_location AS \"Log Source\", count() AS \"Events\","
            f" uniq(device_name) AS \"Agents\", max(wazuh_rule_level) AS \"Max Level\","
            f" uniq(class_name) AS \"OCSF Classes\""
            f" FROM {MERGE} WHERE {TIME} AND src_location != ''"
            f" AND device_name IN (${{device_name:singlequote}})"
            f" GROUP BY src_location ORDER BY Events DESC LIMIT 25")]
    })

    p.append({
        "id": 81, "type": "table", "title": "Decoder → Log Source Matrix",
        "description": "Shows which decoder is parsing which log source. Confirms the correct decoder is firing per source.",
        "datasource": ds(), "gridPos": {"x": 8, "y": 106, "w": 8, "h": 9},
        "options": {"footer": {"show": False}, "showHeader": True},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": [gauge_override("Events", "teal")]},
        "targets": [target(
            f"SELECT decoder_name AS \"Decoder\", src_location AS \"Log Source\","
            f" count() AS \"Events\", uniq(device_name) AS \"Agents\","
            f" uniq(class_name) AS \"OCSF Classes\""
            f" FROM {MERGE} WHERE {TIME} AND decoder_name != ''"
            f" AND device_name IN (${{device_name:singlequote}})"
            f" GROUP BY decoder_name, src_location ORDER BY Events DESC LIMIT 25")]
    })

    p.append({
        "id": 82, "type": "barchart", "title": "Events per Log Source (Top 15)",
        "datasource": ds(), "gridPos": {"x": 16, "y": 106, "w": 8, "h": 9},
        "options": {"orientation": "horizontal", "barRadius": 0.05, "barWidth": 0.7,
                    "stacking": "none", "showValue": "auto", "fillOpacity": 75,
                    "tooltip": {"mode": "single"},
                    "legend": {"displayMode": "list", "placement": "bottom", "showLegend": False}},
        "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "unit": "short"}, "overrides": []},
        "targets": [target(
            f"SELECT src_location AS \"Log Source\", count() AS \"Events\""
            f" FROM {MERGE} WHERE {TIME} AND src_location != ''"
            f" AND device_name IN (${{device_name:singlequote}})"
            f" GROUP BY src_location ORDER BY Events DESC LIMIT 15")]
    })

    p.append({
        "id": 83, "type": "timeseries", "title": "Log Source Volume Over Time",
        "datasource": ds(), "gridPos": {"x": 0, "y": 115, "w": 24, "h": 7},
        "options": {"tooltip": {"mode": "multi", "sort": "desc"},
                    "legend": {"displayMode": "table", "placement": "right", "showLegend": True, "calcs": ["sum"]}},
        "fieldConfig": {"defaults": {"custom": {"lineWidth": 2, "fillOpacity": 4, "spanNulls": False}}, "overrides": []},
        "targets": [target(
            f"SELECT toStartOfInterval(time, INTERVAL $__interval_s SECOND) AS time,"
            f" src_location, count() AS events"
            f" FROM {MERGE} WHERE {TIME} AND src_location != ''"
            f" AND device_name IN (${{device_name:singlequote}})"
            f" AND src_location IN (SELECT src_location FROM {MERGE} WHERE {TIME}"
            f" AND src_location != '' GROUP BY src_location ORDER BY count() DESC LIMIT 10)"
            f" GROUP BY time, src_location ORDER BY time ASC", fmt=3)]
    })

    # ── ROW: ALERT SEARCH ────────────────────────────────────────────────────
    p.append(row_panel(1006, "── ALERT SEARCH ──", 122))

    p.append({
        "id": 70, "type": "table",
        "title": "Recent Alerts — Full Detail (filterable)",
        "description": "All key fields. Use column header filters. finding_uid=Rule ID, finding_types=rule groups, decoder_name=decoder, src_location=log source.",
        "datasource": ds(), "gridPos": {"x": 0, "y": 123, "w": 24, "h": 14},
        "options": {"footer": {"show": False}, "showHeader": True, "sortBy": [{"displayName": "Time", "desc": True}]},
        "fieldConfig": {
            "defaults": {"custom": {"align": "auto", "filterable": True, "inspect": True}},
            "overrides": [
                {"matcher": {"id": "byName", "options": "Time"},        "properties": [{"id": "unit", "value": "dateTimeAsLocal"}, {"id": "custom.width", "value": 165}]},
                {"matcher": {"id": "byName", "options": "Rule ID"},     "properties": [{"id": "custom.width", "value": 80}]},
                level_override(),
                {"matcher": {"id": "byName", "options": "Severity"},    "properties": [{"id": "custom.width", "value": 90}]},
                {"matcher": {"id": "byName", "options": "Agent"},       "properties": [{"id": "custom.width", "value": 110}]},
                {"matcher": {"id": "byName", "options": "OCSF Class"},  "properties": [{"id": "custom.width", "value": 170}]},
                {"matcher": {"id": "byName", "options": "MITRE ID"},    "properties": [{"id": "custom.width", "value": 90}]},
                {"matcher": {"id": "byName", "options": "Src IP"},      "properties": [{"id": "custom.width", "value": 120}]},
                {"matcher": {"id": "byName", "options": "Log Source"},  "properties": [{"id": "custom.width", "value": 180}]}
            ]
        },
        "targets": [target(
            f"SELECT time AS \"Time\", device_name AS \"Agent\","
            f" manager_name AS \"Manager\", src_location AS \"Log Source\","
            f" finding_uid AS \"Rule ID\","
            f" finding_title AS \"Rule Description\", wazuh_rule_level AS \"Level\","
            f" severity AS \"Severity\", class_name AS \"OCSF Class\","
            f" activity_name AS \"Activity\", decoder_name AS \"Decoder\","
            f" finding_types AS \"Rule Groups\", wazuh_fired_times AS \"Fired Times\","
            f" actor_user AS \"User\", src_ip AS \"Src IP\","
            f" dst_ip AS \"Dst IP\", dst_port AS \"Dst Port\","
            f" file_name AS \"File\","
            f" process_name AS \"Process\","
            f" attack_id AS \"MITRE ID\", attack_technique AS \"Technique\","
            f" attack_tactic AS \"Tactic\","
            f" pci_dss AS \"PCI DSS\", gdpr AS \"GDPR\","
            f" hipaa AS \"HIPAA\", nist_800_53 AS \"NIST\""
            f" FROM {MERGE} WHERE {TIME} AND {FILTERS}"
            f" ORDER BY time DESC LIMIT 1000")]
    })

    return p


def soc_dashboard():
    return {
        "__inputs": [{"name": "DS_CLICKHOUSE", "label": "ClickHouse",
                      "description": "ClickHouse datasource", "type": "datasource",
                      "pluginId": "grafana-clickhouse-datasource", "pluginName": "ClickHouse"}],
        "__elements": {},
        "__requires": [
            {"type": "datasource", "id": "grafana-clickhouse-datasource", "name": "ClickHouse", "version": "4.0.0"},
            {"type": "grafana",    "id": "grafana",                       "name": "Grafana",    "version": "10.0.0"}
        ],
        "annotations": {"list": []},
        "description": "Wazuh OCSF SOC – full visibility: overview, agents, rules, MITRE ATT&CK, compliance, alert search.",
        "editable": True,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 1,
        "id": None,
        "links": [],
        "refresh": "30s",
        "schemaVersion": 38,
        "tags": ["wazuh","ocsf","soc","clickhouse","security"],
        "time": {"from": "now-24h", "to": "now"},
        "timepicker": {},
        "timezone": "browser",
        "title": "Wazuh OCSF SOC",
        "uid": "wazuh-ocsf-soc-v2",
        "version": 2,
        "weekStart": "",
        "templating": {"list": [
            {
                "current": {}, "hide": 0, "includeAll": False, "label": "ClickHouse Datasource",
                "multi": False, "name": "DS_CLICKHOUSE", "options": [],
                "query": "grafana-clickhouse-datasource", "refresh": 1, "type": "datasource"
            },
            {
                "current": {"selected": True, "text": "All", "value": "$__all"},
                "datasource": ds(),
                "definition": f"SELECT DISTINCT device_name FROM {MERGE} ORDER BY device_name",
                "hide": 0, "includeAll": True, "label": "Agent", "multi": True,
                "name": "device_name", "options": [],
                "query": f"SELECT DISTINCT device_name FROM {MERGE} ORDER BY device_name",
                "refresh": 2, "sort": 1, "type": "query"
            },
            {
                "current": {"selected": True, "text": "All", "value": "$__all"},
                "datasource": ds(),
                "definition": f"SELECT DISTINCT severity FROM {MERGE} ORDER BY severity",
                "hide": 0, "includeAll": True, "label": "Severity", "multi": True,
                "name": "severity", "options": [],
                "query": f"SELECT DISTINCT severity FROM {MERGE} ORDER BY severity",
                "refresh": 2, "sort": 1, "type": "query"
            },
            {
                "current": {"selected": True, "text": "All", "value": "$__all"},
                "datasource": ds(),
                "definition": f"SELECT DISTINCT class_name FROM {MERGE} ORDER BY class_name",
                "hide": 0, "includeAll": True, "label": "OCSF Class", "multi": True,
                "name": "class_name", "options": [],
                "query": f"SELECT DISTINCT class_name FROM {MERGE} ORDER BY class_name",
                "refresh": 2, "sort": 1, "type": "query"
            },
            {
                "current": {"selected": True, "text": "0", "value": "0"},
                "hide": 0, "includeAll": False, "label": "Min Rule Level",
                "multi": False, "name": "min_level",
                "options": [
                    {"selected": True, "text": "0",  "value": "0"},
                    {"selected": False,"text": "1",  "value": "1"},
                    {"selected": False,"text": "5",  "value": "5"},
                    {"selected": False,"text": "7",  "value": "7"},
                    {"selected": False,"text": "10", "value": "10"},
                    {"selected": False,"text": "12", "value": "12"},
                    {"selected": False,"text": "13", "value": "13"}
                ],
                "query": "0,1,5,7,10,12,13", "type": "custom"
            }
        ]},
        "panels": soc_panels()
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  DASHBOARD 2 — OCSF ETL Pipeline Health
# ═══════════════════════════════════════════════════════════════════════════════

def etl_panels():
    p = []
    m = MERGE

    # ── ROW: PIPELINE HEALTH ─────────────────────────────────────────────────
    p.append(row_panel(2000, "── ETL PIPELINE HEALTH ──", 0))

    # Stats row
    ingestion_stats = [
        (201, "Total Records Ingested",  f"SELECT count() AS \"Total\" FROM {m} WHERE {TIME}", "blue",   0,  1),
        (202, "Records Last 1h",         f"SELECT count() AS \"Last 1h\" FROM {m} WHERE time >= now() - INTERVAL 1 HOUR", "teal",  3,  1),
        (203, "Records Last 5min",       f"SELECT count() AS \"Last 5min\" FROM {m} WHERE time >= now() - INTERVAL 5 MINUTE", "green",  6,  1),
        (204, "Unique Tables Written",   f"SELECT uniq(_table) AS \"Tables\" FROM {m} WHERE {TIME}", "purple", 9,  1),
        (205, "Unique Agent Pipelines",  f"SELECT uniq(device_name) AS \"Agents\" FROM {m} WHERE {TIME}", "teal",  12, 1),
        (206, "Unique OCSF Classes",     f"SELECT uniq(class_name) AS \"Classes\" FROM {m} WHERE {TIME}", "blue",  15, 1),
        (207, "Events With MITRE IDs",   f"SELECT countIf(attack_id != '') AS \"With MITRE\" FROM {m} WHERE {TIME}", "dark-red", 18, 1),
        (208, "Unmapped Events (class=unknown)",
              f"SELECT countIf(class_name = 'Unknown') AS \"Unmapped\" FROM {m} WHERE {TIME}", "yellow", 21, 1),
    ]
    for cid, title, sql, color, gx, gy in ingestion_stats:
        p.append(stat_panel(cid, title, sql, color, gx, gy, gw=3, gh=4, graph_mode="none"))

    # Ingestion rate timeseries
    p.append({
        "id": 210, "type": "timeseries", "title": "Records Ingested per Interval",
        "datasource": ds(), "gridPos": {"x": 0, "y": 5, "w": 16, "h": 8},
        "options": {"tooltip": {"mode": "single"},
                    "legend": {"displayMode": "list", "placement": "bottom", "showLegend": False}},
        "fieldConfig": {"defaults": {"custom": {"lineWidth": 2, "fillOpacity": 15, "gradientMode": "opacity"}, "unit": "short"}, "overrides": []},
        "targets": [{"datasource": ds(),
                     "rawSql": f"SELECT toStartOfInterval(time, INTERVAL $__interval_s SECOND) AS time, count() AS \"Records/interval\" FROM {m} WHERE {TIME} GROUP BY time ORDER BY time ASC",
                     "format": 3, "refId": "A"}]
    })

    # Per-table write volume pie
    p.append({
        "id": 211, "type": "piechart", "title": "Records per Table",
        "datasource": ds(), "gridPos": {"x": 16, "y": 5, "w": 8, "h": 8},
        "options": {"pieType": "donut", "tooltip": {"mode": "multi", "sort": "desc"},
                    "legend": {"displayMode": "table", "placement": "right", "showLegend": True, "values": ["value","percent"]},
                    "displayLabels": ["name"]},
        "fieldConfig": {"defaults": {}, "overrides": []},
        "targets": [{"datasource": ds(),
                     "rawSql": f"SELECT _table AS \"Table\", count() AS \"Records\" FROM {m} WHERE {TIME} GROUP BY _table ORDER BY Records DESC",
                     "format": 1, "refId": "A"}]
    })

    # ── ROW: OCSF FIELD COVERAGE ─────────────────────────────────────────────
    p.append(row_panel(2001, "── OCSF FIELD COVERAGE & TRANSFORMATION ──", 13))

    # Field fill rates - shows how well transformation is working
    p.append({
        "id": 220, "type": "barchart", "title": "OCSF Field Fill Rate (% non-empty)",
        "description": "Shows how many records have each key OCSF field populated — confirms transformation quality.",
        "datasource": ds(), "gridPos": {"x": 0, "y": 14, "w": 24, "h": 10},
        "options": {"orientation": "horizontal", "barRadius": 0.05, "barWidth": 0.8,
                    "stacking": "none", "showValue": "always", "fillOpacity": 75,
                    "tooltip": {"mode": "single"},
                    "legend": {"displayMode": "list", "placement": "bottom", "showLegend": False}},
        "fieldConfig": {
            "defaults": {"color": {"mode": "thresholds"}, "unit": "percent", "min": 0, "max": 100,
                "thresholds": {"mode": "absolute", "steps": [
                    {"color": "dark-red", "value": None},
                    {"color": "orange",   "value": 50},
                    {"color": "yellow",   "value": 75},
                    {"color": "green",    "value": 90}]}},
            "overrides": []
        },
        "targets": [{"datasource": ds(),
                     "rawSql": (
                         f"SELECT field, fill_pct FROM ("
                         f"SELECT 'class_name' AS field,       round(100*countIf(class_name != '') / count(), 1) AS fill_pct FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'severity',                   round(100*countIf(severity != '') / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'finding_uid',                round(100*countIf(finding_uid != '') / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'finding_title',              round(100*countIf(finding_title != '') / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'wazuh_rule_level',           round(100*countIf(wazuh_rule_level > 0) / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'device_name',                round(100*countIf(device_name != '') / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'manager_name',               round(100*countIf(manager_name != '') / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'activity_name',              round(100*countIf(activity_name != '') / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'decoder_name',               round(100*countIf(decoder_name != '') / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'actor_user',                 round(100*countIf(actor_user != '') / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'src_ip',                     round(100*countIf(src_ip != '') / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'dst_ip',                     round(100*countIf(dst_ip != '') / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'file_name',                  round(100*countIf(file_name != '') / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'attack_id (MITRE)',          round(100*countIf(attack_id != '') / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'attack_tactic',              round(100*countIf(attack_tactic != '') / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'pci_dss',                    round(100*countIf(pci_dss != '') / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'gdpr',                       round(100*countIf(gdpr != '') / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'hipaa',                      round(100*countIf(hipaa != '') / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'nist_800_53',                round(100*countIf(nist_800_53 != '') / count(), 1) FROM {m} WHERE {TIME} UNION ALL "
                         f"SELECT 'finding_types (rule groups)',round(100*countIf(finding_types != '') / count(), 1) FROM {m} WHERE {TIME}"
                         f") ORDER BY fill_pct DESC"
                     ),
                     "format": 1, "refId": "A"}]
    })

    # OCSF class distribution over time
    p.append({
        "id": 221, "type": "timeseries", "title": "OCSF Class Volume Over Time",
        "datasource": ds(), "gridPos": {"x": 0, "y": 24, "w": 16, "h": 8},
        "options": {"tooltip": {"mode": "multi", "sort": "desc"},
                    "legend": {"displayMode": "table", "placement": "right", "showLegend": True, "calcs": ["sum"]}},
        "fieldConfig": {"defaults": {"custom": {"lineWidth": 2, "fillOpacity": 5, "spanNulls": False}}, "overrides": []},
        "targets": [{"datasource": ds(),
                     "rawSql": f"SELECT toStartOfInterval(time, INTERVAL $__interval_s SECOND) AS time, class_name, count() AS events FROM {m} WHERE {TIME} GROUP BY time, class_name ORDER BY time ASC",
                     "format": 3, "refId": "A"}]
    })

    # Class breakdown table
    p.append({
        "id": 222, "type": "table", "title": "OCSF Class Breakdown",
        "datasource": ds(), "gridPos": {"x": 16, "y": 24, "w": 8, "h": 8},
        "options": {"footer": {"show": False}, "showHeader": True},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": [gauge_override("Records", "blue")]},
        "targets": [{"datasource": ds(),
                     "rawSql": f"SELECT class_name AS \"OCSF Class\", count() AS \"Records\", round(100*count()/sum(count()) OVER (), 1) AS \"% Total\", uniq(device_name) AS \"Agents\" FROM {m} WHERE {TIME} GROUP BY class_name ORDER BY Records DESC",
                     "format": 1, "refId": "A"}]
    })

    # ── ROW: TRANSFORMATION VALIDATION ──────────────────────────────────────
    p.append(row_panel(2002, "── TRANSFORMATION VALIDATION ──", 32))

    # Null / unmapped events
    p.append({
        "id": 230, "type": "timeseries", "title": "Unmapped Events Over Time (class=Unknown)",
        "description": "Spikes indicate new log sources not yet mapped to OCSF classes.",
        "datasource": ds(), "gridPos": {"x": 0, "y": 33, "w": 12, "h": 7},
        "options": {"tooltip": {"mode": "single"},
                    "legend": {"displayMode": "list", "placement": "bottom", "showLegend": False}},
        "fieldConfig": {"defaults": {"custom": {"lineWidth": 2, "fillOpacity": 20}, "color": {"mode": "fixed", "fixedColor": "yellow"}}, "overrides": []},
        "targets": [{"datasource": ds(),
                     "rawSql": f"SELECT toStartOfInterval(time, INTERVAL $__interval_s SECOND) AS time, count() AS \"Unmapped\" FROM {m} WHERE {TIME} AND class_name = 'Unknown' GROUP BY time ORDER BY time ASC",
                     "format": 3, "refId": "A"}]
    })

    # Missing required fields
    p.append({
        "id": 231, "type": "timeseries", "title": "Events Missing severity Field",
        "description": "Records where severity is empty — indicates mapping gap.",
        "datasource": ds(), "gridPos": {"x": 12, "y": 33, "w": 12, "h": 7},
        "options": {"tooltip": {"mode": "single"},
                    "legend": {"displayMode": "list", "placement": "bottom", "showLegend": False}},
        "fieldConfig": {"defaults": {"custom": {"lineWidth": 2, "fillOpacity": 20}, "color": {"mode": "fixed", "fixedColor": "orange"}}, "overrides": []},
        "targets": [{"datasource": ds(),
                     "rawSql": f"SELECT toStartOfInterval(time, INTERVAL $__interval_s SECOND) AS time, count() AS \"Missing Severity\" FROM {m} WHERE {TIME} AND severity = '' GROUP BY time ORDER BY time ASC",
                     "format": 3, "refId": "A"}]
    })

    # Severity mapping validation
    p.append({
        "id": 232, "type": "piechart", "title": "Severity Value Distribution",
        "description": "Should show only: Critical, High, Medium, Low, Informational. Other values = mapping bug.",
        "datasource": ds(), "gridPos": {"x": 0, "y": 40, "w": 8, "h": 8},
        "options": {"pieType": "pie", "tooltip": {"mode": "multi"},
                    "legend": {"displayMode": "table", "placement": "right", "showLegend": True, "values": ["value","percent"]}},
        "fieldConfig": {"defaults": {}, "overrides": []},
        "targets": [{"datasource": ds(),
                     "rawSql": f"SELECT if(severity='','(empty)',severity) AS \"Severity\", count() AS \"Count\" FROM {m} WHERE {TIME} GROUP BY Severity ORDER BY Count DESC",
                     "format": 1, "refId": "A"}]
    })

    # OCSF class_uid distribution
    p.append({
        "id": 233, "type": "table", "title": "class_uid → class_name Mapping Check",
        "description": "Validates that OCSF class UIDs are correctly assigned. Mismatches indicate transformation bugs.",
        "datasource": ds(), "gridPos": {"x": 8, "y": 40, "w": 8, "h": 8},
        "options": {"footer": {"show": False}, "showHeader": True},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}}, "overrides": [gauge_override("Count", "teal")]},
        "targets": [{"datasource": ds(),
                     "rawSql": f"SELECT class_uid AS \"class_uid\", class_name AS \"class_name\", count() AS \"Count\" FROM {m} WHERE {TIME} GROUP BY class_uid, class_name ORDER BY Count DESC LIMIT 25",
                     "format": 1, "refId": "A"}]
    })

    # Wazuh rule level → OCSF severity mapping check
    p.append({
        "id": 234, "type": "table", "title": "Rule Level → Severity Mapping Check",
        "description": "Verifies that Wazuh rule levels map to correct OCSF severity strings. Wrong values = bug.",
        "datasource": ds(), "gridPos": {"x": 16, "y": 40, "w": 8, "h": 8},
        "options": {"footer": {"show": False}, "showHeader": True},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": [gauge_override("Count", "blue"), max_level_override("Rule Level")]},
        "targets": [{"datasource": ds(),
                     "rawSql": f"SELECT wazuh_rule_level AS \"Rule Level\", severity AS \"Severity\", count() AS \"Count\" FROM {m} WHERE {TIME} GROUP BY wazuh_rule_level, severity ORDER BY wazuh_rule_level DESC LIMIT 25",
                     "format": 1, "refId": "A"}]
    })

    # ── ROW: AGENT INGESTION ─────────────────────────────────────────────────
    p.append(row_panel(2003, "── PER-AGENT INGESTION ──", 48))

    p.append({
        "id": 240, "type": "table", "title": "Per-Agent Ingestion Summary",
        "datasource": ds(), "gridPos": {"x": 0, "y": 49, "w": 24, "h": 8},
        "options": {"footer": {"show": False}, "showHeader": True, "sortBy": [{"displayName": "Records", "desc": True}]},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": [
                            gauge_override("Records", "blue"),
                            {"matcher": {"id": "byName", "options": "First Seen"},
                             "properties": [{"id": "unit", "value": "dateTimeFromNow"}, {"id": "custom.width", "value": 130}]},
                            {"matcher": {"id": "byName", "options": "Last Seen"},
                             "properties": [{"id": "unit", "value": "dateTimeFromNow"}, {"id": "custom.width", "value": 130}]},
                            {"matcher": {"id": "byName", "options": "Fields Empty %"},
                             "properties": [{"id": "unit", "value": "percent"}, {"id": "custom.width", "value": 110},
                                            {"id": "thresholds", "value": {"mode": "absolute", "steps": [
                                                {"color": "green","value": None}, {"color": "yellow","value": 20}, {"color": "red","value": 50}]}},
                                            {"id": "custom.displayMode", "value": "color-background"}]}
                        ]},
        "targets": [{"datasource": ds(),
                     "rawSql": (
                         f"SELECT device_name AS \"Agent\","
                         f" count() AS \"Records\","
                         f" uniq(class_name) AS \"OCSF Classes\","
                         f" uniq(finding_uid) AS \"Unique Rules\","
                         f" uniq(decoder_name) AS \"Decoders\","
                         f" round(100 * countIf(class_name='Unknown') / count(), 1) AS \"Fields Empty %\","
                         f" min(time) AS \"First Seen\","
                         f" max(time) AS \"Last Seen\""
                         f" FROM {m} WHERE {TIME}"
                         f" GROUP BY device_name ORDER BY Records DESC"
                     ),
                     "format": 1, "refId": "A"}]
    })

    # Ingestion rate per agent timeseries
    p.append({
        "id": 241, "type": "timeseries", "title": "Records per Agent Over Time",
        "datasource": ds(), "gridPos": {"x": 0, "y": 57, "w": 24, "h": 8},
        "options": {"tooltip": {"mode": "multi", "sort": "desc"},
                    "legend": {"displayMode": "table", "placement": "right", "showLegend": True, "calcs": ["sum"]}},
        "fieldConfig": {"defaults": {"custom": {"lineWidth": 2, "fillOpacity": 3, "spanNulls": False}}, "overrides": []},
        "targets": [{"datasource": ds(),
                     "rawSql": f"SELECT toStartOfInterval(time, INTERVAL $__interval_s SECOND) AS time, device_name, count() AS records FROM {m} WHERE {TIME} AND device_name IN (SELECT device_name FROM {m} WHERE {TIME} GROUP BY device_name ORDER BY count() DESC LIMIT 10) GROUP BY time, device_name ORDER BY time ASC",
                     "format": 3, "refId": "A"}]
    })

    # ── ROW: TABLE HEALTH ────────────────────────────────────────────────────
    p.append(row_panel(2004, "── CLICKHOUSE TABLE HEALTH ──", 65))

    p.append({
        "id": 250, "type": "table", "title": "ClickHouse Table Row Counts",
        "datasource": ds(), "gridPos": {"x": 0, "y": 66, "w": 12, "h": 8},
        "options": {"footer": {"show": False}, "showHeader": True, "sortBy": [{"displayName": "Rows", "desc": True}]},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": [gauge_override("Rows", "blue")]},
        "targets": [{"datasource": ds(),
                     "rawSql": "SELECT name AS \"Table\", formatReadableQuantity(total_rows) AS \"Rows\", formatReadableSize(total_bytes) AS \"Size\", engine AS \"Engine\" FROM system.tables WHERE database = 'wazuh_ocsf' ORDER BY total_rows DESC",
                     "format": 1, "refId": "A"}]
    })

    p.append({
        "id": 251, "type": "table", "title": "Recent ClickHouse Errors (system.errors)",
        "description": "Any errors here may indicate ingestion or schema issues.",
        "datasource": ds(), "gridPos": {"x": 12, "y": 66, "w": 12, "h": 8},
        "options": {"footer": {"show": False}, "showHeader": True},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "filterable": True}},
                        "overrides": [
                            {"matcher": {"id": "byName", "options": "Count"}, "properties": [
                                {"id": "custom.displayMode", "value": "color-background"},
                                {"id": "thresholds", "value": {"mode": "absolute", "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "orange", "value": 1},
                                    {"color": "dark-red", "value": 10}]}}
                            ]}
                        ]},
        "targets": [{"datasource": ds(),
                     "rawSql": "SELECT name AS \"Error Code\", value AS \"Count\", last_error_time AS \"Last Seen\", last_error_message AS \"Last Message\" FROM system.errors ORDER BY last_error_time DESC LIMIT 20",
                     "format": 1, "refId": "A"}]
    })

    return p


def etl_dashboard():
    return {
        "__inputs": [{"name": "DS_CLICKHOUSE", "label": "ClickHouse",
                      "description": "ClickHouse datasource", "type": "datasource",
                      "pluginId": "grafana-clickhouse-datasource", "pluginName": "ClickHouse"}],
        "__elements": {},
        "__requires": [
            {"type": "datasource", "id": "grafana-clickhouse-datasource", "name": "ClickHouse", "version": "4.0.0"},
            {"type": "grafana",    "id": "grafana",                       "name": "Grafana",    "version": "10.0.0"}
        ],
        "annotations": {"list": []},
        "description": "Wazuh → OCSF ETL pipeline health: ingestion rate, field fill rates, transformation correctness, per-agent stats, ClickHouse table health.",
        "editable": True,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 1,
        "id": None,
        "links": [],
        "refresh": "30s",
        "schemaVersion": 38,
        "tags": ["wazuh","ocsf","etl","pipeline","clickhouse"],
        "time": {"from": "now-24h", "to": "now"},
        "timepicker": {},
        "timezone": "browser",
        "title": "Wazuh OCSF ETL Pipeline Health",
        "uid": "wazuh-ocsf-etl-health-v1",
        "version": 1,
        "weekStart": "",
        "templating": {"list": [
            {"current": {}, "hide": 0, "includeAll": False, "label": "ClickHouse Datasource",
             "multi": False, "name": "DS_CLICKHOUSE", "options": [],
             "query": "grafana-clickhouse-datasource", "refresh": 1, "type": "datasource"}
        ]},
        "panels": etl_panels()
    }


# ─── write ───────────────────────────────────────────────────────────────────

soc = soc_dashboard()
etl = etl_dashboard()

soc_path = os.path.join(BASE, "grafana-dashboard.json")
etl_path = os.path.join(BASE, "grafana-etl-pipeline.json")

with open(soc_path, "w") as f:
    json.dump(soc, f, indent=2)
print(f"Wrote SOC dashboard  → {soc_path}  ({len(soc['panels'])} panels)")

with open(etl_path, "w") as f:
    json.dump(etl, f, indent=2)
print(f"Wrote ETL dashboard  → {etl_path}  ({len(etl['panels'])} panels)")

# quick sanity: re-load both
for path in [soc_path, etl_path]:
    with open(path) as f:
        d = json.load(f)
    ids = [p["id"] for p in d["panels"]]
    assert len(ids) == len(set(ids)), f"Duplicate panel IDs in {path}!"
    print(f"  OK: {path} — {len(ids)} panels, all IDs unique")
