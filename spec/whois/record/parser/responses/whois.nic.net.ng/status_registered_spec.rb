# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.nic.net.ng/status_registered.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.nic.net.ng.rb'

describe Whois::Record::Parser::WhoisNicNetNg, "status_registered.expected" do

  before(:each) do
    file = fixture("responses", "whois.nic.net.ng/status_registered.txt")
    part = Whois::Record::Part.new(:body => File.read(file))
    @parser = klass.new(part)
  end

  describe "#status" do
    it do
      @parser.status.should == :registered
    end
  end
  describe "#available?" do
    it do
      @parser.available?.should == false
    end
  end
  describe "#registered?" do
    it do
      @parser.registered?.should == true
    end
  end
  describe "#created_on" do
    it do
      @parser.created_on.should be_a(Time)
      @parser.created_on.should == Time.parse("2009-05-13 15:27 WAT")
    end
  end
  describe "#updated_on" do
    it do
      @parser.updated_on.should be_a(Time)
      @parser.updated_on.should == Time.parse("2010-07-02 20:06 WAT")
    end
  end
  describe "#expires_on" do
    it do
      @parser.expires_on.should be_a(Time)
      @parser.expires_on.should == Time.parse("2020-07-31 00:00 WAT")
    end
  end
  describe "#nameservers" do
    it do
      @parser.nameservers.should be_a(Array)
      @parser.nameservers.should have(4).items
      @parser.nameservers[0].should be_a(Whois::Record::Nameserver)
      @parser.nameservers[0].name.should == "rns1.nic.net.ng"
      @parser.nameservers[1].should be_a(Whois::Record::Nameserver)
      @parser.nameservers[1].name.should == "rns2.nic.net.ng"
      @parser.nameservers[2].should be_a(Whois::Record::Nameserver)
      @parser.nameservers[2].name.should == "rns3.nic.net.ng"
      @parser.nameservers[3].should be_a(Whois::Record::Nameserver)
      @parser.nameservers[3].name.should == "rns4.nic.net.ng"
    end
  end
end
