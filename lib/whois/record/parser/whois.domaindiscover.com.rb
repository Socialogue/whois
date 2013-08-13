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

      # Parser for the whois.domaindiscover.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author David Hillard
      # @since  2.7.0
      class WhoisDomaindiscoverCom < Base

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
            :name => content_for_scanner[/Registrar:(.+)\n/, 1],
            :url => "www.domaindiscover.com"
          )
        end

        property_supported :admin_contacts do
          build_contact('Administrative Contact:', 'Administrative Contact, Zone Contact:', 'Administrative Contact, Technical Contact, Zone Contact:', Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_contact('Technical Contact:', 'Technical Contact, Zone Contact:', 'Administrative Contact, Technical Contact, Zone Contact:', Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :nameservers do
          if content_for_scanner =~ /Domain servers in listed order:\n\n((.+\n)+)\n/
            $1.split("\n").map do |line|
              Record::Nameserver.new(:name => line.strip)
            end
          end
        end


      private

        def build_registrant_contact(element, type)
          #Rails.logger.debug "build_registrant_contact called"
          match = content_for_scanner.slice(/#{element}\n((.+\n)+)\n/, 1)
          return unless match
          #Rails.logger.debug "build_registrant_contact match!"

          lines = $1.split("\n").map(&:strip)

          Record::Contact.new(
            :type         => type,
            :id           => nil,
            :organization => lines[0].strip, 
            :name         => lines[0].strip, 
            :address      => lines[1].strip, 
            :city         => lines[2].to_s.partition(",")[0],
            :zip          => lines[2].to_s.rpartition(" ")[2],
            :state        => lines[2].to_s.partition(",")[2].rpartition(" ")[0].to_s.strip,
            :country      => lines[3].strip,
            :email        => nil,
            :phone        => nil,
            :fax          => nil
          )
        end

        def build_contact(element1, element2, element3, type)
          #Rails.logger.debug "build_contact called, element=#{element1}"
          match = content_for_scanner.strip.slice(/#{element1}\n((.+\n)+)\n/, 1)
          match = content_for_scanner.strip.slice(/#{element2}\n((.+\n)+)\n/, 1) if !match && element2
          match = content_for_scanner.strip.slice(/#{element3}\n((.+\n)+)\n/, 1) if !match && element3
          return unless match
          #Rails.logger.debug "build_contact match!"

          lines = $1.split("\n").map(&:strip)

          Record::Contact.new(
            :type         => type,
            :id           => nil,
            :organization => lines[0].strip, 
            :name         => lines[1].strip,
            :address      => lines[2].strip,
            :city         => lines[3].to_s.partition(",")[0],
            :zip          => lines[3].to_s.rpartition(" ")[2],
            :state        => lines[3].to_s.partition(",")[2].rpartition(" ")[0].to_s.strip,
            :country      => lines[4].strip,
            :phone        => lines[5].strip,
            :fax          => lines[6].to_s.strip.partition("[fax]")[0],
            :email        => lines[7].strip
          )
        end

      end

    end
  end
end
