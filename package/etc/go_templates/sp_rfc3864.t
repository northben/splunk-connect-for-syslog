        if {
                filter(f_is_not_format);
                parser {
                    syslog-parser(time-zone({{- getenv "SC4S_DEFAULT_TIMEZONE" "00:00"}}) flags(assume-utf8, guess-timezone));
                };
                rewrite(set_rfc3164);        
        };