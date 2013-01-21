#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2012 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/parser/base'


module Whois
  class Record
    class Parser

      # Parser for the whois.tucows.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author Simone Carletti
      # @author Tom Nicholls <tom.nicholls@oii.ox.ac.uk>
      # @since  2.1.0
      class WhoisTucowsCom < Base

        property_not_supported :status

        # The server is contacted only in case of a registered domain.
        property_supported :available? do
          false
        end

        property_supported :registered? do
          !available?
        end


        # property_supported :created_on do
        #   if content_for_scanner =~ /Created on: (.+)\n/
        #     Time.parse($1)
        #   end
        # end
        #
        # property_supported :updated_on do
        #   if content_for_scanner =~ /Last Updated on: (.+)\n/
        #     Time.parse($1)
        #   end
        # end
        #
        # property_supported :expires_on do
        #   if content_for_scanner =~ /Expires on: (.+)\n/
        #     Time.parse($1)
        #   end
        # end


        property_supported :registrar do
          Record::Registrar.new(
            :name => content_for_scanner[/Registered through: (.+)\n/, 1],
            :url => "http://www.tucowsdomains.com/"
          )
        end

        property_supported :registrant_contacts do
          build_registrant_contact('Registrant:', Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact('Administrative Contact:', Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact('Technical Contact:', Record::Contact::TYPE_TECHNICAL)
        end


        property_supported :nameservers do
          if content_for_scanner =~ /Domain servers in listed order:\n((.+\n)+)\n/
            $1.split("\n").map do |line|
              Record::Nameserver.new(:name => line.strip)
            end
          end
        end


      private

      def build_registrant_contact(element, type)
        match = content_for_scanner.slice(/#{element}\n((.+\n)+)\n/, 1)
        return unless match

        # Lines 1 and 5 may be absent, depending on the record.
        # The parser attempts to correct for this, but may be a bit flaky
        # on non-standard data.
        #
        # e.g.:
        # 0 Tucowsdomains.com, Inc., tucows.com, Inc.  dns@jomax.net
        # 1 tucows.com, Inc.
        # 2 14455 N Hayden Rd Suite 219
        # 3 Scottsdale, Arizona 85260
        # 4 United States
        # 5 +1.4805058800      Fax -- +1.4805058844

        lines = $1.split("\n").map(&:strip)
        full_address = lines.length >= 4 ? lines[-3] : ""
        full_address =  lines[-4] + "\n" +full_address if lines.length >= 5

        Record::Contact.new(
          :type         => type,
          :id           => nil,
          :name         => lines[0].to_s.gsub(/\s\S+@[^\.].*\.[a-z]{2,}\s?\)?$/, "").strip,
          :organization => lines[0].to_s.gsub(/\s\S+@[^\.].*\.[a-z]{2,}\s?\)?$/, "").strip,
          :address      => full_address,
          :city         => lines.length >= 4 ? lines[-2].to_s.partition(",")[0] : "",
          :zip          => lines.length >= 4 ? lines[-2].to_s.rpartition(" ")[2] : "",
          :state        => lines.length >= 4 ? lines[-2].to_s.partition(",")[2].rpartition(" ")[0].to_s.strip : "",
          :country      => lines.length >= 4 ? lines[-1] : "",
          :phone        => nil,
          :fax          => nil,
          :email        => lines[0].to_s.scan(/[^\s]\S+@[^\.].*\.[a-z]{2,}[^\s\)\n]/).first
        )
      end

        def build_contact(element, type)
          match = content_for_scanner.slice(/#{element}\n((.+\n)+)\n/, 1)
          return unless match

          lines = $1.split("\n").map(&:strip)
          full_address = lines.length >= 5 ? lines[-4].to_s : ""
          full_address =  lines[-5].to_s + "\n" +full_address if lines.length >= 6

          phone = nil
          fax   = nil
          if lines[-1].to_s =~ /Fax:/
            phone, fax = lines.delete_at(-1).to_s.scan(/^(.*) Fax:(.*)$/).first
            phone = phone.strip
            fax   = fax.strip
          else
            phone = lines[-1].to_s.strip
          end

          Record::Contact.new(
            :type         => type,
            :id           => nil,
            :name         => lines[0].to_s.gsub(/\s\S+@[^\.].*\.[a-z]{2,}\s?\)?$/, "").strip,
            :organization => lines[0].to_s.gsub(/\s\S+@[^\.].*\.[a-z]{2,}\s?\)?$/, "").strip,
            :address      => full_address,
            :city         => lines.length >= 4 ? lines[-3].to_s.partition(",")[0] : "",
            :zip          => lines.length >= 4 ? lines[-3].to_s.rpartition(" ")[2] : "",
            :state        => lines.length >= 4 ? lines[-3].to_s.partition(",")[2].rpartition(" ")[0].to_s.strip : "",
            :country      => lines.length >= 4 ? lines[-2] : "",
            :phone        => phone,
            :fax          => fax,
            :email        => lines[0].to_s.scan(/[^\s]\S+@[^\.].*\.[a-z]{2,}[^\s\)\n]/).first
          )
        end

      end

    end
  end
end
