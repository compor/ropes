#!/usr/bin/env python

# simple SSH automations and scripts
# Christos Vassiladiotis
# cvassiladiotis@gmail.com

#TODO check command line password obfuscation/hide
#TODO check performance in general (e.g. without loading all file lines)
#TODO check to see if put/get file routines can be merged
#TODO check if ssh.close() operations require try/catch block to avoid unexpected exits

import sys
import os
import errno
import time
import array
import traceback
import socket
import paramiko
from paramiko import SSHException
from operator import itemgetter
from optparse import Option, OptionValueError, OptionParser, OptionGroup

version_string = "%prog 0.26"


# hide command line arguments from showing in operating system process listings

magic_separator = "^&^0bfUs^&~"
magic_env_var_name = "rop_argument_line"

if len( sys.argv ) > 1 :
  #print sys.argv

	argument_line = ""
	program = sys.argv[ 0 ]

	for argument in sys.argv:
		argument_line = argument_line + magic_separator + argument

	os.putenv( "magic_env_var_name", argument_line )

	os.execl( program, program )
else:
	argument_line = os.getenv( "magic_env_var_name" )

	if argument_line is None:
		sys.exit( 1 )
	else:
		argument_line = os.getenv( "magic_env_var_name" )
		os.unsetenv( "magic_env_var_name" )

	#print argument_line


### defaults

# default directories for SFTP transfers
default_local_dir = "."
default_remote_dir = "."

# a connection attempt to a port uses the timeout
# from the same corresponding index of the timeout array
default_port = [ 22 ]
default_timeout = [ 30 ] # seconds

# default sleep interval between individual operations
default_sleep_interval = 0 # seconds

# default SSH username
default_username = 'root'

# output file suffixes
result_file_suffix = ".result"
error_file_suffix = ".error"
paramiko_log_file_suffix = ".paramiko.log"



# remote operations option parser callback
def check_rop_callback( option, opt_str, value, parser ):
	if not value[ 0 ].isdigit():
		raise OptionValueError( "option %s: invalid operation priority : %r" % ( opt_str, value ) )

	t = ( int( value[ 0 ] ), value[ 1 ] )
	v = getattr( parser.values, option.dest )

	if v is None:
		v = [ t ]
	else:
		v.append( t )

	setattr( parser.values, option.dest, v )


# print same output to multiple file streams
def print_output( output_streams_list, data_out ):
	for j in range( len( output_streams_list ) ):
		output_streams_list[ j ].write( data_out )
		output_streams_list[ j ].flush()


# execute a list of commands on a remote host over an established SSH connection
def execute_commands( ssh_session, command_list, multiline ):
	if command_list is None:
		return

	result = [ "" * len( command_list ) ]

	for i in range( len( command_list ) ):
		try:
			ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command( command_list[ i ] )
			data = ssh_stdout.readlines()
		except SSHException, e:
			print_output( [ sys.stderr ], '\ncaught exception: %s: %s' % ( e.__class__, e ) )
			if options.verbose:
				traceback.print_exc( file = sys.stderr )

			data = None

	if len( data ) <= 0:
		if multiline:
			result[ i ] = [ 'error:%d:nodata' % ( i + 1 ) ]
		else:
			result[ i ] = 'error:%d:nodata' % ( i + 1 )
	else:
		if multiline:
			for j in range( len( data ) ):
				data[ j ] = data[ j ].strip()
				result[ i ] = data
		else:
			result[ i ] = data[ len( data ) - 1 ].strip()

	for i in range( len( command_list ) ):
		if not multiline and result[ i ].find( ' ' ) != -1:
			res = "\"" + result[ i ] + "\""
		else:
			res = result[ i ]

	if not multiline:
		print_output( [ sys.stdout, fout ], "\t" )

	if multiline:
		for j in range( len( res ) ):
			print_output( [ sys.stdout, fout ], "%s\n" % res[ j ] )
	else:
		print_output( [ sys.stdout, fout ], "%s" % res )


# setup absolute directory names for local and remote directories
def setup_dirs( ssh_session, local_dir, remote_dir ):
	pwd = ""

	if not remote_dir[ 0 ].startswith( "/" ):
		ssh_transport = ssh_session.get_transport()
		scp = ssh_transport.open_sftp_client()
	try:
		pwd = scp.normalize( remote_dir )
	except Exception, e:
		print_output( [ sys.stderr ], '\ncaught exception: %s: %s' % ( e.__class__, e ) )
		if options.verbose:
			traceback.print_exc( file = sys.stderr )

		scp.close()

	if not local_dir[ 0 ].startswith( "/" ):
		if local_dir[ 0 ].startswith( "." ):
			local_dir = os.getcwd() + local_dir[ 1: ]
		else:
			local_dir = os.getcwd() + local_dir

	return ( local_dir, remote_dir )


# put a list of files on a remote host over an established SSH connection
def put_files( ssh_session, put_files_list, local_dir, remote_dir, multiline ):
	if put_files_list is None:
		return

	result = [ "" * len( put_files_list ) ]

	for i in range( len( put_files_list ) ):
		result[ i ] = "file:%d:\"%s\":error" % ( i + 1, put_files_list[ i ] )

	ssh_transport = ssh_session.get_transport()
	scp = ssh_transport.open_sftp_client()

	try:
		for i in range( len( put_files_list ) ):
			if not put_files_list[ i ].startswith( '/' ):
				localfile = local_dir + "/" + put_files_list[ i ]
				remotefile = remote_dir + "/" + put_files_list[ i ]
			else:
				localfile = remotefile = put_files_list[ i ]

			scp.put( localfile, remotefile )

			statinfo_message = os.stat( localfile )
			scp.chmod( remotefile, statinfo_message.st_mode )

			result[ i ] = "file:%d:\"%s\":done" % ( i + 1, remotefile )
	except Exception, e:
		print_output( [ sys.stderr ], '\ncaught exception: %s: %s' % ( e.__class__, e ) )
		if options.verbose:
			traceback.print_exc( file = sys.stderr )

	for i in range( len( put_files_list ) ):
		if multiline:
			print_output( [ sys.stdout, fout ], "\n" )
		else:
			print_output( [ sys.stdout, fout ], "\t" )

	print_output( [ sys.stdout, fout ], result[ i ] )

	scp.close()


# get a list of files from a remote host over an established SSH connection
def get_files( ssh_session, get_files_list, local_dir, remote_dir, suffix, multiline ):
	if get_files_list is None:
		return

	result = [ "" * len( get_files_list ) ]

	for i in range( len( get_files_list ) ):
		result[ i ] = "file:%d:\"%s\":error" % ( i + 1, get_files_list[ i ] )

	ssh_transport = ssh_session.get_transport()
	scp = ssh_transport.open_sftp_client()

	# if no suffix is provided, use the currently connected ip
	# or else the files transferred will be overwritten
	# when more than 1 IP's are provided
	if suffix is None or suffix == '':
		( peer_name, peer_ip ) = ssh_transport.getpeername()
		suffix = peer_ip

	try:
		for i in range( len( get_files_list ) ):
			if not get_files_list[ i ].startswith( '/' ):
				localfile = local_dir + "/" + get_files_list[ i ] + "_" + suffix
				remotefile = remote_dir + "/" + get_files_list[ i ]
			else:
				localfile = remotefile = get_files_list[ i ]

			scp.get( remotefile, localfile )

			statinfo_message = scp.stat( remotefile )
			print statinfo_message
			os.chmod( localfile, statinfo_message.st_mode )

			result[ i ] = "file:%d:\"%s\":done" % ( i + 1, localfile )
	except Exception, e:
		print_output( [ sys.stderr ], '\ncaught exception: %s: %s' % ( e.__class__, e ) )
		if options.verbose:
			traceback.print_exc( file = sys.stderr )

		for i in range( len( get_files_list ) ):
			if multiline:
				print_output( [ sys.stdout, fout ], "\n" )
			else:
				print_output( [ sys.stdout, fout ], "\t" )

		print_output( [ sys.stdout, fout ], result[ i ] )

		scp.close()


# command line argument parsing
parser = OptionParser( usage = "usage: %prog {general options} {operations} [operation options]", version = version_string )

general_option_parser = OptionGroup( parser, "General Options" )
operations_option_parser = OptionGroup( parser, "Operations" )
opoptions_option_parser = OptionGroup( parser, "Operation Options" )

general_option_parser.add_option( "-q", "--quiet", action = "store_false", dest = "verbose", default = True, help = "disable verbose output (store)" )
general_option_parser.add_option( "-f", "--file", action = "store", dest = "filename", help = "input file name (store)" )
general_option_parser.add_option( "-i", "--ip", action = "append", dest = "ip", help = "peer IP (append)" )
general_option_parser.add_option( "-u", "--username", action = "store", dest = "username", default = default_username, help = "SSH username [ default : \"%default\" ] (store)" )
general_option_parser.add_option( "-p", "--password", action = "store", dest = "password", help = "SSH password (store)" )
general_option_parser.add_option( "-R", "--record-separator", action = "store", dest = "record_separator", help = "record separator string per peer access (store)" )
general_option_parser.add_option( "-m", "--multiline", action = "store_true", dest = "multiline", default = False, help = "grab multiline output (store)" )
general_option_parser.add_option( "-P", "--port", type = "int", action = "append", dest = "port", help = "SSH ports [ default : %s ] (append)" % default_port )
general_option_parser.add_option( "-t", "--timeout", type = "int", action = "append", dest = "timeout", help = "SSH operations timeouts [ default : %s secs ] (append)" % default_timeout )
general_option_parser.add_option( "-k", "--keepalive", type = "int", action = "store", dest = "keepalive", help = "SSH channel keepalive interval [ secs ] (store)" )
general_option_parser.add_option( "-s", "--sleep-interval", type = "int", action = "store", default = default_sleep_interval, dest = "sleep_interval", help = "sleep interval between operations [ default : %default secs ] (store)" )

operations_option_parser.add_option( "-c", "--command", nargs = 2, type = "string", action = "callback", dest = "command", callback = check_rop_callback, metavar = "PRIORITY COMMAND", help = "command to be executed on the remote host (append)" )
operations_option_parser.add_option( "-C", "--command_file", nargs = 2, type = "string", action = "callback", dest = "command_file", callback = check_rop_callback, metavar = "PRIORITY COMMAND", help = "file containing command to be executed on the remote host (append)" )
operations_option_parser.add_option( "-U", "--put-file", nargs = 2, type = "string", action = "callback", dest = "put_file", callback = check_rop_callback, metavar = "PRIORITY FILE", help = "put file on remote host with SFTP aka upload (append)" )
operations_option_parser.add_option( "-D", "--get-file", nargs = 2, type = "string", action = "callback", dest = "get_file", callback = check_rop_callback, metavar = "PRIORITY FILE", help = "get file from remote host with SFTP aka download (append)" )

opoptions_option_parser.add_option( "-l", "--local-dir", action = "store", default = default_local_dir, dest = "local_dir", help = "local dir for SFTP transfers [ default : \"%s\" ] (store)" % default_local_dir )
opoptions_option_parser.add_option( "-r", "--remote-dir", action = "store", default = default_remote_dir, dest = "remote_dir", help = "remote dir for SFTP transfers [ default : \"%s\" ] (store)" % default_remote_dir )
# TODO fix its usage
#opoptions_option_parser.add_option( "", "--ip-suffix", action = "store_true", default = False, dest = "ip_suffix", help = "use peer ip for suffix of received file" )

parser.add_option_group( general_option_parser )
parser.add_option_group( operations_option_parser )
parser.add_option_group( opoptions_option_parser )

( options, args ) = parser.parse_args( argument_line.split( magic_separator ) )

# various argument sanity and constraint checks

if not options.port:
	options.port = default_port
if not options.timeout:
	options.timeout = default_timeout

if options.filename and options.ip:
	parser.error( "cannot specify both an input file name or peer IP" )
if not options.filename and not options.ip:
	parser.error( "must specify either an input file name or peer IP" )
if not options.password:
	parser.error( "missing SSH password" )
if options.command is None and options.command_file is None and options.put_file is None and options.get_file is None:
	parser.error( "an operation must be specified" )


if options.filename:
	output_filename = options.filename
else:
	output_filename = "output"


# hide the password, if provided by command line arguments
ssh_password = options.password
options.password = ''

# merge and sort operations by priority while tagging
# each operation with a self-descriptive, unique name
operation = []

if options.command is not None:
	for i in range( len( options.command ) ):
		operation.append( ( options.command[ i ][ 0 ], 'command', options.command[ i ][ 1 ] ) )

if options.command_file is not None:
	for i in range( len( options.command_file ) ):
		# TODO needs file operation checks
		command_string = open( options.command_file[ i ][ 1 ], 'r' ).read()
		operation.append( ( options.command_file[ i ][ 0 ], 'command', command_string ) )

if options.put_file is not None:
	for i in range( len( options.put_file ) ):
		operation.append( ( options.put_file[ i ][ 0 ], 'put', options.put_file[ i ][ 1 ] ) )

if options.get_file is not None:
	for i in range( len( options.get_file ) ):
		operation.append( ( options.get_file[ i ][ 0 ], 'get', options.get_file[ i ][ 1 ] ) )

operation = sorted( operation, key = itemgetter( 0 ) )

# since the operations are sorted, we compare 2 adjacent operations for identical priority
if len( operation ) - 1 > 1:
	for i in range( len( operation ) - 1 ):
		if( operation[ i ][ 0 ] == operation[ i + 1 ][ 0 ] ):
			parser.error( "operation priorities must differ : %s %s" % ( operation[ i ], operation[ i + 1 ] ) )

# each port uses its own associated timeout, so we need to pad
# the main timeout array with the default timeout for the extra ports to use it
padded_timeouts_number = len( options.port ) > len( options.timeout )

if padded_timeouts_number > 0:
	for i in range( padded_timeouts_number ):
		options.timeout.append( default_timeout[ 0 ] )

if options.verbose:
	print_output( [ sys.stderr ], "\nexecuted : %s\n" % args )
	print_output( [ sys.stderr ], "\nexecuted with options : %s\n" % options )
	print_output( [ sys.stderr ], "\noperations : \n" )

	for op in operation:
		print_output( [ sys.stderr ], "priority : %d, type : %s, context : \"%s\"\n" % op )


# setup paramiko logging
paramiko.util.log_to_file( output_filename + paramiko_log_file_suffix, 10 )

try:
	if options.filename:
		# input file is expected to be a file containing line separated IP's
		fin = open( options.filename, 'r' )
		file_lines = fin.readlines()
		fin.close()
	else:
		ips = options.ip
		file_lines = ips

	# logs all successful results and the error message of the last attempt
	# upon failing to access a terminal
	# that way each IP is listed only once
	fout = open( output_filename + result_file_suffix, 'w' )

	# logs all errors from every unsuccessful attempt
	# that way each IP might be listed max N times,
	# where N is the number of ports to be tried
	ferr = open( output_filename + error_file_suffix, 'w' )

	print_output( [ sys.stdout ], "\n\n" )

	# iterate over each ip and try each port with its corresponding timeout

	for line in file_lines:
		line_list = line.split()
		ip = line_list[ 0 ].strip()

		specific_port = 0

		if len( line_list ) > 1:
			specific_port = int( line_list[ 1 ].strip() )

		ports_number = range( len( options.port ) )

		# if a specific port is declared for this ip then do not pay attention to overall ports settings
		if specific_port:
			ports_number = range( 1 )

		if not ip:
			continue

		print_output( [ sys.stdout ], "\n" )


		for i in ports_number:
			ssh = paramiko.SSHClient()
			ssh.set_missing_host_key_policy( paramiko.AutoAddPolicy() )

			if specific_port:
				port = specific_port
			else:
				port = options.port[ i ]

			try:
				print_output( [ sys.stdout ], "attempting ssh %s@%s:%s with %s secs timeout\n" % ( options.username, ip, port, options.timeout[ i ] ) )

				ssh.connect( ip, port, options.username, ssh_password, timeout = options.timeout[ i ] )
			except socket.error, e:
				# in the case of a socket error, we distinguish between 'connection refused' and all others
				# if we get a 'connection refused' error, it means that the peer is up,
				# but there is no ssh service on that port, so we need to try the next denoted port

				print_output( [ sys.stderr ], '\ncaught exception: %s: %s' % ( e.__class__, e ) )
				if options.verbose:
					traceback.print_exc( file = sys.stderr )

				info_message = "%s\t%s\t%s\n" % ( ip, port,"error:\"" + e.__str__() + "\"" )
				print_output( [ sys.stdout, ferr ], info_message )

				# check if the socket error is a 'connection refused'
				if e.args[ 0 ] == errno.ECONNRESET or e.args[ 0 ] == errno.ECONNABORTED:
					# if it is the last attempted port, something needs to be logged
					if i == ( len( options.port ) - 1 ):
						print_output( [ fout ], info_message )

					ssh.close()

					# try the next port, the host is up
					# but no ssh service on this port
					continue
				else:
					print_output( [ fout ], info_message )

					ssh.close()

					# skip the remaining ports
					break
			except Exception, e:
				print_output( [ sys.stderr ], '\ncaught exception: %s: %s' % ( e.__class__, e ) )
				if options.verbose:
					traceback.print_exc( file = sys.stderr )

				info_message = "%s\t%s\n" % ( ip, "error:\"" + e.__str__() + "\"" )
				print_output( [ sys.stderr, ferr ], info_message )

				if i == ( len( options.port ) - 1 ):
					print_output( [ fout ], info_message )

				ssh.close()

				# try the next port, the host is up but an error occurred
				continue
			else:
				# GREAT SUCCESS!!!
				print_output( [ sys.stdout ], "connection to %s@%s:%s succeeded\n" % ( options.username, ip, port ) )

				if options.record_separator:
					print_output( [ sys.stdout, fout ], options.record_separator + "\n" )

				if options.keepalive and options.keepalive != 0:
					ssh_transport = ssh.get_transport()
					ssh_transport.set_keepalive( options.keepalive )

				print_output( [ sys.stdout, fout ], "%s" % ( ip ) )

				if options.multiline:
					print_output( [ sys.stdout, fout ], "\n" )

				# the directories setup is only valid for the same ssh connection
				# so we need to reset them when we have established a new one
				local_dir = remote_dir = ""

				for k in range( len( operation ) ):
					# sleep only when we have a meaningful sleep interval
					# and only after the first operation is done
					if k > 0 and options.sleep_interval > 0:
						time.sleep( options.sleep_interval )

					( prio, type, op ) = operation[ k ]

					if type == 'put' or type == 'get':
						if local_dir == "" or remote_dir == "":
							( local_dir, remote_dir ) = setup_dirs( ssh, options.local_dir, options.remote_dir )

					if type == 'command':
						execute_commands( ssh, [ op ], options.multiline )
					elif type == 'put':
						put_files( ssh, [ op ], local_dir, remote_dir, options.multiline )
					elif type == 'get':
						get_files( ssh, [ op ], local_dir, remote_dir, "", options.multiline )
						#get_files( ssh, [ op ], local_dir, remote_dir, tid, options.multiline )
					else:
						pass

					if not options.multiline:
						print_output( [ sys.stdout, fout ], "\n" )

					# successfully accessed a port so skip the remaining (if any) ports listed

					ssh.close()

					break
except IOError, e:
	print_output( [ sys.stderr ], '\ncaught exception: %s: %s' % ( e.__class__, e ) )
	if options.verbose:
		traceback.print_exc( file = sys.stderr )

	sys.exit( 1 )
except KeyboardInterrupt, e:
	print_output( [ sys.stderr ], '\ncaught exception: %s: %s' % ( e.__class__, e ) )
	if options.verbose:
		traceback.print_exc( file = sys.stderr )

	sys.exit( 1 )

fout.close()
ferr.close()

sys.exit( 0 )
