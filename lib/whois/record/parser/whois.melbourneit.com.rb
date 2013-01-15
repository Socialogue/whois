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

      # Parser for the whois.melbourneit.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author David Hillard
      # @since  2.7.0
      class WhoisMelbourneitCom < Base

        property_not_supported :status

        # The server is contacted only in case of a registered domain.
        property_supported :available? do
          false
        end

        property_supported :registered? do
          !available?
        end

        property_supported :registrar do
          Record::Registrar.new(
            :name => content_for_scanner[/Registrar: (.+)\n/, 1],
            :url => "http://www.melbourneit.com"
          )
        end

        property_supported :registrant_contacts do
          build_registrant_contact('Domain Name..........', Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_admin_contact('Admin Name...........', Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_technical_contact('Tech Name............', Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :nameservers do
          if content_for_scanner =~ /Name Server..........((.+\n)+)\n/
            $1.split("\n").map do |line|
              Record::Nameserver.new(:name => line.strip)
            end
          end
        end


      private

        def build_registrant_contact(element, type)
          match = content_for_scanner.slice(/#{element}((.+\n)+)\n/, 1)
          return unless match

          # The registrar MelbourneIt.com appears to have a very 
          # consistent output, making for easy parsing.
          # Fixed location for each record object is assumed. 

          lines = $1.split("\n").map(&:strip)
          
          address1 = lines[5].rpartition("Organisation Address.")[2].strip
          address2 = lines[6].rpartition("Organisation Address.")[2].strip
          address3 = lines[7].rpartition("Organisation Address.")[2].strip
          full_address = address1
          full_address = full_address + "\n" + address2 if address2 and address2 != ""
          full_address = full_address + "\n" + address3 if address3 and address3 != ""

          Record::Contact.new(
            :type         => type,
            :id           => nil,
            :organization => lines[4].rpartition("Organisation Name....")[2].strip,
            :name         => nil, 
            :address      => full_address,
            :city         => lines[8].rpartition("Organisation Address.")[2].strip,
            :zip          => lines[9].rpartition("Organisation Address.")[2].strip,
            :state        => lines[10].rpartition("Organisation Address.")[2].strip,
            :country      => lines[11].rpartition("Organisation Address.")[2].strip,
            :email        => nil,
            :phone        => nil,
            :fax          => nil
          )
        end

        def build_admin_contact(element, type)
          match = content_for_scanner.slice(/#{element}((.+\n)+)\n/, 1)
          return unless match

          # The registrar MelbourneIt.com appears to have a very 
          # consistent output, making for easy parsing.
          # Fixed location for each record object is assumed. 

          lines = $1.split("\n").map(&:strip)

          Record::Contact.new(
            :type         => type,
            :id           => nil,
            :organization => nil,
            :name         => lines[0].rpartition("Admin Address........")[2].strip, 
            :address      => lines[1].rpartition("Admin Address........")[2].strip,
            :city         => lines[4].rpartition("Admin Address.")[2].strip,
            :zip          => lines[5].rpartition("Admin Address........")[2].strip,
            :state        => lines[6].rpartition("Admin Address........")[2].strip,
            :country      => lines[7].rpartition("Admin Address........")[2].strip,
            :email        => lines[8].rpartition("Admin Email..........")[2].strip,
            :phone        => lines[9].rpartition("Admin Phone..........")[2].strip,
            :fax          => lines[10].rpartition("Admin Fax............")[2].strip
          )
        end

        def build_technical_contact(element, type)
          match = content_for_scanner.slice(/#{element}((.+\n)+)\n/, 1)
          return unless match

          # The registrar MelbourneIt.com appears to have a very 
          # consistent output, making for easy parsing.
          # Fixed location for each record object is assumed. 

          lines = $1.split("\n").map(&:strip)

          Record::Contact.new(
            :type         => type,
            :id           => nil,
            :organization => nil,
            :name         => lines[0].rpartition("Tech Address.........")[2].strip, 
            :address      => lines[1].rpartition("Tech Address.........")[2].strip,
            :city         => lines[4].rpartition("Tech Address.........")[2].strip,
            :zip          => lines[5].rpartition("Tech Address.........")[2].strip,
            :state        => lines[6].rpartition("Tech Address.........")[2].strip,
            :country      => lines[7].rpartition("Tech Address.........")[2].strip,
            :email        => lines[8].rpartition("Tech Email...........")[2].strip,
            :phone        => lines[9].rpartition("Tech Phone...........")[2].strip,
            :fax          => lines[10].rpartition("Tech Fax.............")[2].strip
          )
        end

      end

    end
  end
end
