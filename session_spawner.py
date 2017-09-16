#!/usr/bin/env python

# October 2010
# Intralot S.A.

import sys
import os
import traceback
from optparse import Option, OptionParser, OptionGroup

version_string = "\n\
%prog\n\
version : 0.004\n\
Copyright (C) 2010 Intralot S.A.\n"

try:

# command line argument parsing
    parser = OptionParser( usage = "usage: %prog {general options}", version = version_string )

    general_option_group = OptionGroup( parser, "General Options" )

    general_option_group.add_option( "-q", "--quiet", action = "store_false", 
                       dest = "verbose", default = True, help = "disable verbose output" )
    general_option_group.add_option( "-f", "--file", action = "store",
                       dest = "filename", help = "input file name prefix" )
    general_option_group.add_option( "-i", "--iterations", action = "store", type = "int",
                       dest = "iterations", help = "number of iterations" )
    general_option_group.add_option( "-s", "--session-name", action = "store",
                       dest = "session", help = "screen session name" )
    general_option_group.add_option( "-c", "--command", action = "store",
                       dest = "command", help = "command" )

    parser.add_option_group( general_option_group )

    ( options, args ) = parser.parse_args( sys.argv )

    if not options.filename:
        parser.error( "must specify input file name prefix" )
    if not options.iterations:
        parser.error( "must specify iterations" )
    if not options.session:
        parser.error( "must specify session name" )
    if not options.command:
        parser.error( "must specify command string" )

    if options.verbose:
        print sys.argv

    for i in range( options.iterations ):
        c = "screen -S %s%02d -md %s %s%02d" % ( options.session, i, options.command, options.filename, i )
        if options.verbose:
            print c
        os.system( c )

except KeyboardInterrupt, e:
    print '\ncaught exception: %s: %s' % ( e.__class__, e )
    if options.verbose:
        traceback.print_exc( file = sys.stderr )

    sys.exit( 1 )

sys.exit( 0 )
