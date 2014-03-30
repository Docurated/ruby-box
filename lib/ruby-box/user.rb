module RubyBox
  class User < Item

    def enterprise
      reload_field("enterprise")
    end

    def role
      reload_field("role")
    end

    private

    def reload_field field
      @fields ||= { }
      @fields[field] ||= begin
        resp = @session.get( "#{RubyBox::API_URL}/users/#{id}?fields=#{ field }" )
        resp[field]
      end
      @fields[field]
    end

    def resource_name
      'users'
    end

  end
end
