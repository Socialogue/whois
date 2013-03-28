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

      # Parser for the whois.domain.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author David Hillard
      # @since  2.7.0
      class WhoisDomainCom < Base

        property_not_supported :status

        # The server is contacted only in case of a registered domain.
        property_supported :available? do
          false
        end

        property_supported :registered? do
          !available?
        end

        property_supported :registrant_contacts do
          build_registrant_contact('Registrant:', Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :registrar do
          Record::Registrar.new(
            :name => content_for_scanner[/Registrar Name....: (.+)\n/, 1],
            :url => "www.domain.com"
          )
        end

        property_supported :admin_contacts do
          build_contact('Administrative Contact:', Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact('Technical Contact:', Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :nameservers do
          if content_for_scanner =~ /DNS Servers:\n\n((.+\n)+)\n/
            $1.split("\n").map do |line|
              Record::Nameserver.new(:name => line.strip)
            end
          end
        end


      private

        def build_registrant_contact(element, type)
          match = content_for_scanner.slice(/#{element}\n((.+\n)+)\n/, 1)
          return unless match

          # The registrar Domain.com appears to have a very 
          # consistent output, making for easy parsing.
          # Fixed location for each record object assumed. 
          # No FAX, name, phone or email is included in the registrant contact info.

          lines = $1.split("\n").map(&:strip)
          full_address = lines.length > 3 ? lines[-3].to_s : ""
          full_address =  lines[-4].to_s + "\n" + full_address if lines.length > 4

          Record::Contact.new(
            :type         => type,
            :id           => nil,
            :organization => lines[0].strip, 
            :name         => nil, 
            :address      => full_address, 
            :city         => lines.length > 4 ? lines[3].to_s.partition(",")[0] : lines[2].to_s.partition(",")[0],
            :zip          => lines.length > 4 ? lines[3].to_s.rpartition(" ")[2] : lines[2].to_s.rpartition(" ")[2],
            :state        => lines.length > 4 ? lines[3].to_s.partition(",")[2].rpartition(" ")[0].to_s.strip : lines[2].to_s.partition(",")[2].rpartition(" ")[0].to_s.strip,
            :country      => lines.length > 4 ? lines[4].strip : lines[3].strip,
            :email        => nil,
            :phone        => nil,
            :fax          => nil
          )
        end

        def build_contact(element, type)
          match = content_for_scanner.slice(/#{element}\n((.+\n)+)\n/, 1)
          return unless match

          # The registrar Domain.com appears to have a very 
          # consistent output, making for easy parsing.
          # Fixed location for each record object assumed.

          lines = $1.split("\n").map(&:strip)
          email_address = lines[0].strip.rpartition(" ")[2].strip
          full_address = lines.length > 4 ? lines[-4].to_s : ""
          full_address =  lines[-5].to_s + "\n" + full_address if lines.length > 5
          fax_included = lines.length > 5 ? lines[5].downcase.include?("fax:") : lines[4].downcase.include?("fax:")
          fax_number = lines.length > 5 ? lines[5].to_s.rpartition(":")[2].strip : lines[4].to_s.rpartition(":")[2].strip if fax_included

          Record::Contact.new(
            :type         => type,
            :id           => nil,
            :organization => nil, 
            :name         => lines[0].strip[0..(lines[0].strip.length - (email_address.length+1))], 
            :address      => full_address, 
            :city         => lines.length > 5 ? lines[3].to_s.partition(",")[0] : lines[2].to_s.partition(",")[0],
            :zip          => lines.length > 5 ? lines[3].to_s.rpartition(" ")[2] : lines[2].to_s.rpartition(" ")[2],
            :state        => lines.length > 5 ? lines[3].to_s.partition(",")[2].rpartition(" ")[0].to_s.strip : lines[2].to_s.partition(",")[2].rpartition(" ")[0].to_s.strip,
            :country      => lines.length > 5 ? lines[4].strip : lines[3].strip,
            :email        => email_address,
            :phone        => lines.length > 5 ? lines[5].partition(" ")[0].strip : lines[4].partition(" ")[0].strip, 
            :fax          => fax_number
          )
        end

      end

    end
  end
end
