class KeysController < ApplicationController
  unloadable

  before_action :find_project_by_project_id
  before_action :authorize
  before_action :find_key, only: [:show, :edit, :update, :destroy, :copy]
  before_action :find_keys, only: [:context_menu]
  accept_api_auth :index, :show

  helper :sort
  include SortHelper
  helper ContextMenusHelper

  def index
    unless Setting.plugin_vault['use_redmine_encryption'] || Setting.plugin_vault['use_null_encryption']
      if !Setting.plugin_vault['encryption_key'] || Setting.plugin_vault['encryption_key'].empty?
        render_error t("error.key.not_set")
        return
      end
    end

    sort_init 'name', 'asc'
    sort_update 'name' => "#{Vault::Key.table_name}.name"

    @query = params[:query]

    @search_fild = params[:search_fild] || 'name'

    if @query
      if @query.match(/#/)
        tag_string = (@query.match(/(#)([^,]+)/))[2]
        tag = Vault::Tag.find_by_name(tag_string)
        @keys = tag.nil? ? nil : tag.keys.where(project: @project)
      else
        @keys = case @search_fild
                when 'name'
                  @project.keys.where(name: @query)
                when 'url'
                  @project.keys.where(url: @query)
                when 'tag'
                  tag = Vault::Tag.find_by_name(@query)
                  tag.nil? ? nil : tag.keys.where(project: @project)
                end
      end
    else
      @keys = @project.keys
    end

    @keys = @keys.order(sort_clause) unless @keys.nil?
    @keys = @keys.select { |key| key.whitelisted?(User, @project) } unless @keys.nil?
    @keys = [] if @keys.nil?

    @limit = per_page_option
    @key_count = @keys.count
    @key_pages = Paginator.new @key_count, @limit, params[:page]
    @offset ||= @key_pages.offset

    @keys = @keys.drop(@offset).first(@limit) if @key_count > 0
    @keys.map(&:decrypt!)

    respond_to do |format|
      format.html
      format.pdf
      format.json { render json: @keys }
    end
  end

  def new
    @key = Vault::Key.new(project: @project)
    @key.whitelist = ""
    @key
  end

  def copy
    @key = Vault::Key.new(project: @key.project, name: @key.name, login: @key.login, type: @key.type)
    render action: 'new'
  end

  def create
    save_file if key_params[:file]
    @key = Vault::Key.new(key_params)
    @key.project = @project

    self.update_wishlist

    respond_to do |format|
      if @key.save
        format.html { redirect_to project_keys_path(@project), notice: t('notice.key.create.success') }
      else
        format.html { render action: 'new' }
      end
    end
  end

  def update
    save_file if key_params[:file]
    respond_to do |format|
      self.update_wishlist

      Rails.logger.info "Key params: #{key_params}"
      if @key.update(key_params)
        format.html { redirect_to project_keys_path(@project), notice: t('notice.key.update.success') }
      else
        format.html { render action: 'edit' }
      end
    end
  end

  def update_wishlist
    if User.current.allowed_to?(:manage_whitelist_keys, @key.project)
      @key.whitelist = params[:whitelist].blank? ? "" : params[:whitelist].join(",")
    end
  end

  def edit
    if !@key.whitelisted?(User, @project)
      render_error t("error.key.not_whitelisted")
    else
      @key.decrypt!
      respond_to do |format|
        format.html { render action: 'edit' }
      end
    end
  end

  def show
    if !@key.whitelisted?(User, @project)
      render_error t("error.key.not_whitelisted")
    else
      @key.decrypt!
      respond_to do |format|
        format.html { render action: 'show' }
      end
    end
  end

  def destroy
    Vault::Key.find(params[:id]).destroy
    redirect_to project_keys_path(@project)
    flash[:notice] = t('notice.key.delete.success')
  end

  def context_menu
    @keys.map(&:decrypt!)
    render layout: false
  end

  private

  def find_key
    @key = Vault::Key.find(params[:id])
    unless @key.project_id == @project.id
      redirect_to project_keys_path(@project), notice: t('alert.key.not_found')
    end
  end

  def find_keys
    @keys = Vault::Key.find(params[:ids])
    unless @keys.all? { |k| k.project_id == @project.id }
      redirect_to project_keys_path(@project), notice: t('alert.key.not_found')
    end
  end

  def key_params
    params.require(:vault_key).permit(:type, :name, :body, :login, :file, :url, :comment, :tags)
  end

  def index_params
    params.permit('query')
  end

  def save_file
    name = SecureRandom.uuid
    File.open("#{Vault::KEYFILES_DIR}/#{name}", "wb") { |f| f.write(key_params[:file].read) }
    params['vault_key']['file'] = name
  end
end
