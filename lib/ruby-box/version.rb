module RubyBox
    class Version < Item

        private

        def resource_name
            'versions'
        end

        def has_mini_format?
            true
        end
    end
end
