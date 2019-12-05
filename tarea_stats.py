import pdb
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.recoco import Timer
from collections import defaultdict
from pox.openflow.discovery import Discovery
from pox.lib.util import dpid_to_str
import time
import json


import pandas as pd
from sklearn import metrics
from sklearn.model_selection import train_test_split
from sklearn import tree
from sklearn.impute import SimpleImputer
import numpy as np


def safe_min(values):
    if not values:
        return 0.0
    else:
        return min(values)


def safe_max(values):
    if not values:
        return 0.0
    else:
        return min(values)


def mean(values):
    if not values:
        return 0
    return float(sum(values))/float(len(values))


class tableStats(EventMixin):
    def __init__(self, interval=10, dry_run=0, train_data='', min_packets=0, min_duration=0):
        self.tableActiveCount = {}
        self.interval = interval
        self.last_time = time.time()
        self.flow_statistics = {}
        self.dry_run = (dry_run == 1)
        self.min_packets = min_packets
        self.min_duration = min_duration
        self.CLASSIFIER = None
        core.openflow.addListeners(self)
        self.train_classifier(train_data)

    def _handle_ConnectionUp(self, event):
        print "Switch %s has connected" % event.dpid
        self.sendTableStatsRequest(event)

    def registerMatch(self, stat):
        flow_key = "{} {}".format(stat.match.nw_dst, stat.match.nw_src)
        current_time = time.time()
        if flow_key in self.flow_statistics:
            # This is a "backward flow"
            current_stat = self.flow_statistics[flow_key]
            if stat.packet_count > 0:
                current_stat["biat"] += [(current_time - self.last_time) /
                                         stat.packet_count] * stat.packet_count
        else:
            flow_key = "{} {}".format(stat.match.nw_src, stat.match.nw_dst)
            current_stat = self.flow_statistics.get(flow_key, {
                "flow_key": flow_key,
                "nw_src": str(stat.match.nw_src),
                "nw_dst": str(stat.match.nw_dst),
                "dl_src": str(stat.match.dl_src),
                "dl_dst": str(stat.match.dl_dst),
                "byte_count": 0,
                "packets": 0,
                "last_time_seen": current_time,
                "last_time_update": current_time,
                "first_time_seen": current_time,
                "fiat": [],
                "biat": [],
                "flowiat": [],
                "fb_psec": [],
                "fp_psec": [],
                "is_attack": False,
                "is_not_attack": True
            })
            if stat.packet_count > 0:
                current_stat["fiat"] += [(current_time - self.last_time) /
                                         stat.packet_count] * stat.packet_count
        # Bidirectional statistics
        current_stat["fb_psec"] += [stat.byte_count / (current_time - self.last_time)] * int(
            round(current_time - self.last_time))
        current_stat["fp_psec"] += [stat.packet_count / (current_time - self.last_time)] * int(
            round(current_time - self.last_time))
        if stat.packet_count > 0:
            current_stat["flowiat"] += [(current_time - self.last_time) /
                                        stat.packet_count] * stat.packet_count
        current_stat["byte_count"] += stat.byte_count
        current_stat["packets"] += stat.packet_count
        current_stat["last_time_seen"] = current_time
        current_stat["last_time_update"] = current_time

        current_stat["duration"] = current_stat["last_time_seen"] - \
            current_stat["first_time_seen"]
        current_stat["total_fiat"] = sum(current_stat["fiat"])
        current_stat["total_biat"] = sum(current_stat["biat"])
        current_stat["min_fiat"] = safe_min(current_stat["fiat"])
        current_stat["min_biat"] = safe_min(current_stat["biat"])
        current_stat["max_fiat"] = safe_max(current_stat["fiat"])
        current_stat["max_biat"] = safe_max(current_stat["biat"])
        current_stat["mean_fiat"] = mean(current_stat["fiat"])
        current_stat["mean_biat"] = mean(current_stat["biat"])
        current_stat["flowPktsPerSecond"] = mean(current_stat["fp_psec"])
        current_stat["flowBytesPerSecond"] = mean(current_stat["fb_psec"])
        current_stat["min_flowiat"] = safe_min(current_stat["flowiat"])
        current_stat["max_flowiat"] = safe_max(current_stat["flowiat"])
        current_stat["mean_flowiat"] = mean(current_stat["flowiat"])
        current_stat["std_flowiat"] = np.std(current_stat["flowiat"])

        self.flow_statistics[flow_key] = current_stat

        return flow_key

    def _handle_FlowStatsReceived(self, event):
        processed_flows = []
        for f in event.stats:
            processed_flows += [self.registerMatch(f)]

        # Update attack/normal status on flows
        normal_flows, attack_flows = self.classify_flows(processed_flows)

        for flow_key in attack_flows:
            flow = self.flow_statistics[flow_key]["is_attack"] = True
        
        for flow_key in attack_flows:
            flow = self.flow_statistics[flow_key]["is_attack"] = False

        for stat in event.stats:
            self.block_flow(event, stat)

        self.last_time = time.time()
        Timer(self.interval, self.sendTableStatsRequest, args=[event])

    def block_flow(self, event, stat):
        flow_key = "{} {}".format(stat.match.nw_src, stat.match.nw_dst)
        flow = self.flow_statistics.get(flow_key, None)
        if not flow:
            return
        if (flow["is_attack"] and
            (flow["packets"] > self.min_packets) and
                (flow["duration"] >= self.min_duration)):
            if not self.dry_run:
                print("Blocking from {} to {}".format(
                    stat.match.nw_src, stat.match.nw_dst))
                block = of.ofp_match()
                block = stat.match
                flow_mod = of.ofp_flow_mod()
                flow_mod.match = block
                event.connection.send(flow_mod)
            else:
                print("Dryrun Blocking from {} to {}".format(
                    stat.match.nw_src, stat.match.nw_dst))

    def sendTableStatsRequest(self, event):
        event.connection.send(of.ofp_stats_request(
            body=of.ofp_flow_stats_request()))
        print "Send flow stat message to Switch %s " % event.dpid

    @staticmethod
    def replace_missing_value(df, features):
        imputer = SimpleImputer(strategy="median")
        df_num = df[features]
        imputer.fit(df_num)
        X = imputer.transform(df_num)
        res_def = pd.DataFrame(X, columns=df_num.columns)
        return res_def

    def train_classifier(self, train_data):
        df = pd.read_csv(train_data)
        clf = tree.DecisionTreeClassifier()

        features = ["duration",
                    "total_fiat", "total_biat",
                    "min_fiat", "min_biat",
                    "max_fiat", "max_biat",
                    "mean_fiat", "mean_biat",
                    "flowPktsPerSecond", "flowBytesPerSecond",
                    "min_flowiat", "max_flowiat", "mean_flowiat", "std_flowiat"]
        dfX = self.replace_missing_value(df, features)
        dfY = df[["is_attack"]]

        dfXnz = dfX[dfX["duration"] > 0]
        dfYnz = dfY[dfX["duration"] > 0]

        self.CLASSIFIER = self.do_training(clf, dfXnz, dfYnz)

    @staticmethod
    def do_training(clf, dfX, dfYo):
        dfX = dfX.astype('float32')
        dfY = pd.get_dummies(dfYo, drop_first=False, prefix="", prefix_sep="")

        X_train, X_test, y_train, y_test = train_test_split(
            dfX, dfY, test_size=0.20, random_state=42, stratify=dfYo)
        clf = clf.fit(X_train, y_train)

        # Check results
        expected = y_test
        predicted = clf.predict(X_test)
        expected_cat = expected.idxmax(axis=1)
        predicted_cat = pd.DataFrame(
            predicted, columns=dfY.columns).idxmax(axis=1)

        report = metrics.classification_report(expected_cat, predicted_cat)

        # Print results
        print("Classification report for classifier %s:\n%s\n"
              % (clf, report))
        print()
        print("Confusion matrix:\n%s" % metrics.confusion_matrix(
            expected_cat, predicted_cat, labels=dfY.columns))
        return clf

    def classify_flows(self, flow_keys):
        if not flow_keys:
            return [], []
        df = pd.DataFrame([self.flow_statistics[key] for key in flow_keys])

        features = ["duration",
                    "total_fiat", "total_biat",
                    "min_fiat", "min_biat",
                    "max_fiat", "max_biat",
                    "mean_fiat", "mean_biat",
                    "flowPktsPerSecond", "flowBytesPerSecond",
                    "min_flowiat", "max_flowiat", "mean_flowiat", "std_flowiat"]
        dfX = self.replace_missing_value(df, features)
        predicted = pd.DataFrame(self.CLASSIFIER.predict(
            dfX), index=flow_keys).idxmax(axis=1)

        return predicted[predicted == 0].index.tolist(), predicted[predicted == 1].index.tolist()


def launch(interval='5', dry_run='0', train_data="", min_packets=0, min_duration=0):
    interval = int(interval)
    dry_run = int(dry_run)
    min_packets = int(min_packets)
    min_duration = int(min_duration)
    core.registerNew(tableStats, interval, dry_run, train_data, min_packets, min_duration)
