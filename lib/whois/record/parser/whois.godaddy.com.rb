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

      # Parser for the whois.godaddy.com server.
      #
      # @see Whois::Record::Parser::Example
      #   The Example parser for the list of all available methods.
      #
      # @author Simone Carletti
      # @author Tom Nicholls <tom.nicholls@oii.ox.ac.uk>
      # @since  2.1.0
      class WhoisGodaddyCom < Base

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

        #Rails.logger.debug("GODADDY - called")
        property_supported :registrar do
          Record::Registrar.new(
            :name => content_for_scanner[/Registrar Expiration Date:(.+)\n/, 1],
            :url => "http://www.godaddy.com/"
          )
        end

        property_supported :registrant_contacts do
          build_registrant_contact('Registrant Name:', Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_admin_contact('Admin Name:', Record::Contact::TYPE_ADMIN)
        end

        property_supported :technical_contacts do
          build_tech_contact('Tech Name:', Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :nameservers do
          if content_for_scanner =~ /Name Server:\n((.+\n)+)\n/
            $1.split("\n").map do |line|
              Record::Nameserver.new(:name => line.strip)
              #Rails.logger.debug("GODADDY - nameserver found = #{line.strip}")
            end
          end
        end


        private

        def build_registrant_contact(element, type)
          match = content_for_scanner.slice(/#{element}((.+\n)+)\n/, 1)
          #Rails.logger.debug("GODADDY build_registrant_contact match = #{match}, element=#{element}, content=#{content_for_scanner}.")
          return unless match

          # Lines 1 and 5 may be absent, depending on the record.
          # The parser attempts to correct for this, but may be a bit flaky
          # on non-standard data.
          #
          # 0 GoDaddy.com, Inc., GoDaddy.com, Inc.  dns@jomax.net
          # 1 GoDaddy.com, Inc.
          # 2 14455 N Hayden Rd Suite 219
          # 3 Scottsdale, Arizona 85260
          # 4 United States
          # 5 +1.4805058800      Fax -- +1.4805058844

          lines = $1.split("\n").map(&:strip)
        
          Record::Contact.new(
            :type         => type,
            :id           => nil,
            :name         => lines[0].rpartition("Registrant Name:")[2].strip, 
            :organization => lines[1].rpartition("Registrant Organization:")[2].strip,
            :address      => lines[2].rpartition("Registrant Street:")[2].strip,
            :city         => lines[3].rpartition("Registrant City:")[2].strip,
            :state        => lines[4].rpartition("Registrant State/Province:")[2].strip,
            :zip          => lines[5].rpartition("Registrant Postal Code:")[2].strip,
            :country      => lines[6].rpartition("Registrant Country:")[2].strip,
            :email        => nil,
            :phone        => nil,
            :fax          => nil
          )
        end

        def build_admin_contact(element, type)
          match = content_for_scanner.slice(/#{element}((.+\n)+)\n/, 1)
          #Rails.logger.debug("GODADDY build_admin_contact match = #{match}, element=#{element}, content=#{content_for_scanner}.")
          return unless match
  
          # Lines 1 and 5 may be absent, depending on the record.
          # The parser attempts to correct for this, but may be a bit flaky
          # on non-standard data.
          #
          # 0 GoDaddy.com, Inc., GoDaddy.com, Inc.  dns@jomax.net
          # 1 GoDaddy.com, Inc.
          # 2 14455 N Hayden Rd Suite 219
          # 3 Scottsdale, Arizona 85260
          # 4 United States
          # 5 +1.4805058800      Fax -- +1.4805058844

          lines = $1.split("\n").map(&:strip)
        
          Record::Contact.new(
            :type         => type,
            :id           => nil,
            :name         => lines[0].rpartition("Admin Name:")[2].strip, 
            :organization => lines[1].rpartition("Admin Organization:")[2].strip,
            :address      => lines[2].rpartition("Admin Street:")[2].strip,
            :city         => lines[3].rpartition("Admin City:")[2].strip,
            :state        => lines[4].rpartition("Admin State/Province:")[2].strip,
            :zip          => lines[5].rpartition("Admin Postal Code:")[2].strip,
            :country      => lines[6].rpartition("Admin Country:")[2].strip,
            :phone        => lines[7].rpartition("Admin Phone:")[2].strip,
            :fax          => lines[8].rpartition("Admin Fax:")[2].strip,
            :email        => lines[9].rpartition("Admin Email:")[2].strip
          )
        end

        def build_tech_contact(element, type)
          match = content_for_scanner.slice(/#{element}((.+\n)+)\n/, 1)
          #Rails.logger.debug("GODADDY build_tech_contact match = #{match}, element=#{element}, content=#{content_for_scanner}.")
          return unless match

          # Lines 1 and 5 may be absent, depending on the record.
          # The parser attempts to correct for this, but may be a bit flaky
          # on non-standard data.
          #
          # 0 GoDaddy.com, Inc., GoDaddy.com, Inc.  dns@jomax.net
          # 1 GoDaddy.com, Inc.
          # 2 14455 N Hayden Rd Suite 219
          # 3 Scottsdale, Arizona 85260
          # 4 United States
          # 5 +1.4805058800      Fax -- +1.4805058844

          lines = $1.split("\n").map(&:strip)
        
          Record::Contact.new(
            :type         => type,
            :id           => nil,
            :name         => lines[0].rpartition("Tech Name:")[2].strip, 
            :organization => lines[1].rpartition("Tech Organization:")[2].strip,
            :address      => lines[2].rpartition("Tech Street:")[2].strip,
            :city         => lines[3].rpartition("Tech City:")[2].strip,
            :state        => lines[4].rpartition("Tech State/Province:")[2].strip,
            :zip          => lines[5].rpartition("Tech Postal Code:")[2].strip,
            :country      => lines[6].rpartition("Tech Country:")[2].strip,
            :phone        => lines[7].rpartition("Tech Phone:")[2].strip,
            :fax          => lines[8].rpartition("Tech Fax:")[2].strip,
            :email        => lines[9].rpartition("Tech Email:")[2].strip
          )
        end

      end
    end
  end
end
