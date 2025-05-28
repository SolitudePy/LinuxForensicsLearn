FROM jekyll/jekyll:latest

# Copy Gemfile and Gemfile.lock to install dependencies
COPY ./Gemfile /srv/jekyll/Gemfile
COPY ./Gemfile.lock /srv/jekyll/Gemfile.lock

# Install dependencies
WORKDIR /srv/jekyll
RUN bundle install

# Set the default command
CMD ["bundle", "exec", "jekyll", "serve", "--host", "0.0.0.0"]
