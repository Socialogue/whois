#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2012 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/scanners/base'


module Whois
  class Record
    module Scanners

      # Scanner for the whois.audns.net.au record.
      #
      # @since  2.5.0
      class WhoisAudnsNetAu < Base

        self.tokenizers += [
            :skip_empty_line,
            :scan_available,
            :scan_keyvalue,
        ]


        tokenizer :scan_available do
          if @input.skip(/^No Data Found\n/)
            @ast["status:available"] = true
          end
        end

      end

    end
  end
end
