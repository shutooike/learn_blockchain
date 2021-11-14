FROM ruby:3.0
WORKDIR /app
ADD Gemfile* $WORKDIR/
RUN bundle install
