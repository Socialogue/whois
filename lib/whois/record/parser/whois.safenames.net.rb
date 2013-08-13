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

      # Parser for the whois.Safenames.net server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author D. Hillard
      # @since  2.7.4
      class WhoisSafenamesNet < Base

        #Rails.logger.debug("Safenames - called")

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
            :name => content_for_scanner[/Expiration Date:(.+)\n/, 1],
            :url => "http://www.safenames.com/"
          )
        end

        property_supported :registrant_contacts do
          build_contact('REGISTRANT', Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact('ADMIN', Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact('TECHNICAL', Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :nameservers do
          if content_for_scanner =~ /Name Server:\n((.+\n)+)\n/
            $1.split("\n").map do |line|
              Record::Nameserver.new(:name => line.strip)
            end
          end
        end


        private

        def build_contact(element, type)
          #Rails.logger.debug("Safenames.net -build_contact element=#{element}, content=#{content_for_scanner}")
          match = content_for_scanner.strip.slice(/\[#{element}\]\n((.+\n)+)\n/, 1)
          return unless match

          lines = $1.split("\n").map(&:strip)
          return unless lines
          
          return unless lines.count > 10
          
          address1 = lines[2].rpartition("Address Line 1:")[2].strip
          address2 = lines[3].rpartition("Address Line 2:")[2].strip
          full_address = address1
          full_address = full_address + "\n" + address2 if address2 and address2 != ""
          #Rails.logger.debug("Safenames.net -build_contact building record, full_address=#{full_address}")
            
          Record::Contact.new(
            :type         => type,
            :id           => nil,
            :organization => lines[0].rpartition("Organisation Name:")[2].strip,
            :name         => lines[1].rpartition("Contact Name:")[2].strip, 
            :address      => full_address,
            :city         => lines[4].rpartition("City / Town:")[2].strip,
            :state        => lines[5].rpartition("State / Province:")[2].strip,
            :zip          => lines[6].rpartition("Zip / Postcode:")[2].strip,
            :country      => lines[7].rpartition("Country:")[2].strip,
            :phone        => lines[8].rpartition("Telephone:")[2].strip,
            :fax          => lines[9].rpartition("Fax:")[2].strip,
            :email        => lines[10].rpartition("Email:")[2].strip
          )
        end
      end
    end
  end
end
