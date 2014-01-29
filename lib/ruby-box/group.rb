module RubyBox
  class Group < Item

    has_many :memberships

    def add_membership member, role="member"
      uri = URI.parse( "#{RubyBox::API_URL}/group_memberships" )
      request = Net::HTTP::Post.new( uri.request_uri )
      request.body = JSON.dump({
        "user" => {"id" => member.id},
        "group" => {"id" => id},
        "role" => role
      })

      @session.request(uri, request)

      self
    end

    private

    def has_mini_format?
      true
    end

    def resource_name
      'groups'
    end
  end
end
