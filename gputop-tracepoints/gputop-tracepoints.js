#!/usr/bin/env node
'use strict';

/*
 * Copyright (C) 2016 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

const Gputop = require('gputop');
const ArgumentParser = require('argparse').ArgumentParser;

/* Don't want to pollute CSV output to stdout with log messages... */
var stderr_log = new console.Console(process.stderr, process.stderr);

function GputopTool()
{
    Gputop.Gputop.call(this);

    this.metric = undefined;

    this.counters_ = [];

    this.write_queued_ = false;

    this.console = {
        log: (msg) => {
            if (args.debug)
                stderr_log.log(msg);
        },
        warn: (msg) => {
            if (args.debug)
                stderr_log.warn(msg);
        },
        error: (msg) => {
            stderr_log.error(msg);
        },
    };
}

GputopTool.prototype = Object.create(Gputop.Gputop.prototype);

GputopTool.prototype.list_tracepoints = function(features) {
    stderr_log.log('List of tracepoints:');
    for (var i = 0; i < features.tracepoints.length; i++) {
        stderr_log.log(features.tracepoints[i]);
    }
};

GputopTool.prototype.update_features = function(features) {
    if (features.tracepoints.length === 0) {
        console.error("No tracepoints supported");
        process.exit(1);
        return;
    }

    var tracepoints = args.tracepoints.split(",");

    if (tracepoints.length == 0) {
        this.list_tracepoints(features)
        process.exit(1);
        return;
    }

    if (args.tracepoint_info) {
        for (var i = 0; i < tracepoints.length; i++) {
            this.get_tracepoint_info(tracepoints[i], (info) => {
                stderr_log.log("i915 tracepoint info = " + JSON.stringify(info, 2));
            });
        }
        process.exit(0);
        return;
    }

    if (args.record) {
        for (var i = 0; i < tracepoints.length; i++) {
            this.get_tracepoint_info(tracepoints[i], (info) => {
                this.open_tracepoint(info, {}, () => {
                    stderr_log.log("Tracepoint opened");
                });
            });
        }
    }
}


var parser = new ArgumentParser({
    version: '0.0.1',
    addHelp: true,
    description: "GPU Top GputopTool"
});

parser.addArgument(
    [ '-a', '--address' ],
    {
        help: 'host:port to connect to (default localhost:7890)',
        defaultValue: 'localhost:7890'
    }
);

parser.addArgument(
    [ '-d', '--debug' ],
    {
        help: "Verbose debug output",
        action: 'storeTrue',
        defaultValue: false
    }
);

parser.addArgument(
    [ '-i', '--tracepoint-info' ],
    {
        help: "Print information about a tracepoint",
        action: 'storeTrue',
        defaultValue: false
    }
);

parser.addArgument(
    [ '-s', '--search' ],
    {
        help: "Search tracepoints",
        defaultValue: undefined
    }
);

parser.addArgument(
    [ '-t', '--tracepoints' ],
    {
        help: "A list of tracepoints",
        defaultValue: [],
        nargs: '?'
    }
);

var args = parser.parseArgs();

var gputop = new GputopTool();

gputop.connect(args.address, () => {
    stderr_log.log("Connected");
});
