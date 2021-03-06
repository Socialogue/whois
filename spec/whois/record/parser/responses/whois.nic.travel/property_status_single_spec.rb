# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.nic.travel/property_status_single.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.nic.travel.rb'

describe Whois::Record::Parser::WhoisNicTravel, "property_status_single.expected" do

  subject do
    file = fixture("responses", "whois.nic.travel/property_status_single.txt")
    part = Whois::Record::Part.new(:body => File.read(file))
    described_class.new(part)
  end

  describe "#status" do
    it do
      subject.status.should == ["ok"]
    end
  end
end
