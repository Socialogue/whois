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

      # Parser for the whois.corporatedomains.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author David Hillard
      # @since  2.7.0
      class WhoisCorporatedomainsCom < Base

        property_not_supported :status

        # The server is contacted only in case of a registered domain.
        property_supported :available? do
          false
        end

        property_supported :registered? do
          !available?
        end

        property_supported :registrant_contacts do
          build_contact('Registrant: ', nil, Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :registrar do
          Record::Registrar.new(
            :name => content_for_scanner[/Registrar Name....: (.+)\n/, 1],
            :url => "www.cscprotectsbrands.com"
          )
        end

        property_supported :admin_contacts do
          build_contact('Administrative Contact:', 'Administrative,Technical Contact:', Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact('Technical Contact:', 'Administrative,Technical Contact:', Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :nameservers do
          if content_for_scanner =~ /DNS Servers:\n\n((.+\n)+)\n/
            $1.split("\n").map do |line|
              Record::Nameserver.new(:name => line.strip)
            end
          end
        end


      private

        def build_contact(element1, element2, type)
          match = content_for_scanner.slice(/#{element1}\n((.+\n)+)\n/, 1)
          match = content_for_scanner.slice(/#{element2}\n((.+\n)+)\n/, 1) if !match && element2
          return unless match

          # The registrar CorporateDomains.com appears to have a very 
          # consistent output, making for easy parsing.
          # Fixed location for each record object assumed. No FAX support.

          lines = $1.split("\n").map(&:strip)

          Record::Contact.new(
            :type         => type,
            :id           => nil,
            :organization => lines[0].strip, #lines[0].to_s.gsub(/\s\S+@[^\.].*\.[a-z]{2,}\s?\)?$/, "").strip,
            :name         => lines[1].strip, #lines[1].to_s.gsub(/\s\S+@[^\.].*\.[a-z]{2,}\s?\)?$/, "").strip,
            :address      => lines[2].strip, #lines[2].to_s.gsub(/\s\S+@[^\.].*\.[a-z]{2,}\s?\)?$/, "").strip,
            :city         => lines[3].to_s.partition(",")[0],
            :zip          => lines[3].to_s.rpartition(" ")[2],
            :state        => lines[3].to_s.partition(",")[2].rpartition(" ")[0].to_s.strip,
            :country      => lines[4].strip,
            :email        => lines.length > 6 ? lines[6].rpartition(":")[2].strip : lines[5].rpartition(" ")[2].strip, #lines[5].to_s.scan(/[^\s]\S+@[^\.].*\.[a-z]{2,}[^\s\)\n]/).first
            :phone        => lines.length > 6 ? lines[5].rpartition(" ")[2].strip : nil, #lines[5].delete_at(-1).to_s.scan(/^(.*)
            :fax          => nil
          )
        end

      end

    end
  end
end
