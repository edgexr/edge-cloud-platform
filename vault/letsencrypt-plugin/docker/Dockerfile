FROM ruby:2.6

RUN apt-get update -qq && apt-get install -y \
	build-essential \
	cron \
	python3-acme \
	python3-certbot \
	python3-mock \
	python3-openssl \
	python3-pkg-resources \
	python3-pyparsing \
	python3-zope.interface \
	python3-certbot-nginx \
	python3-certbot-dns-cloudflare \
	supervisor

ENV APP_HOME /app
RUN mkdir $APP_HOME
WORKDIR $APP_HOME

COPY supervisord.conf /etc
COPY run.sh $APP_HOME
COPY crontab /etc/crontab

COPY Gemfile Gemfile.lock $APP_HOME/
RUN bundle install

COPY app.rb $APP_HOME

CMD [ "./run.sh" ]
