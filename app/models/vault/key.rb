module Vault
  require 'csv'
  require 'iconv'

  class Vault::Key < ActiveRecord::Base
    belongs_to :project
		# TODO: remove tags temporary
		#has_and_belongs_to_many :tags
    unloadable

    def tags=(tags_string)
      @tags = Vault::Tag.create_from_string(tags_string)
    end

    def encrypt!
      self
    end

    def decrypt!
      self
    end

    def self.import(file)
      CSV.foreach(file.path, headers: true) do |row|
        rhash = row.to_hash

        decryptb = Encryptor::decrypt(rhash['body'])

        key = Vault::Key.where(name: rhash['name']).first

        unless key
          begin
            Vault::Key.create(
              project_id: rhash['project_id'],
              name: rhash['name'],
              body: decryptb,
              login: rhash['login'],
              type: rhash['type'],
              file: rhash['file'],
              url: rhash['url'],
              comment: rhash['comment'],
              whitelist: rhash['comment']
            ).update_column(:id, rhash['id'])
          rescue StandardError => e
            Rails.logger.error "Error creating key: #{e.message}"
          end
        else
          begin
            key.update(
              project_id: rhash['project_id'],
              name: rhash['name'],
              body: decryptb,
              login: rhash['login'],
              type: rhash['type'],
              file: rhash['file'],
              url: rhash['url'],
              comment: rhash['comment'],
              whitelist: rhash['comment']
            )
          rescue StandardError => e
            Rails.logger.error "Error updating key: #{e.message}"
          end
        end
      end
    end

    def whitelisted?(user, project)
      return true if user.current.admin || !user.current.allowed_to?(:whitelist_keys, project)
      self.whitelist.split(',').each do |id|
        return true if User.in_group(id).where(id: user.current.id).exists?
      end
      self.whitelist.split(',').include?(user.current.id.to_s)
    end
  end

  class Vault::KeysVaultTags < ActiveRecord::Base
  end
end
