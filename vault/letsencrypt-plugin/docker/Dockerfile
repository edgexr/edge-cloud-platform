FROM ruby:2.6

RUN apt-get update -qq && apt-get install -y \
	build-essential \
	cron \
	python3-pip \
	supervisor

RUN pip install -U pip && pip3 install \
	certbot \
	certbot-nginx \
	certbot-dns-cloudflare \
	certbot-dns-nsone

ENV APP_HOME /app
RUN mkdir $APP_HOME
WORKDIR $APP_HOME

COPY supervisord.conf /etc
COPY run.sh $APP_HOME
COPY crontab /etc/crontab

COPY Gemfile Gemfile.lock $APP_HOME/
RUN bundle install

COPY app.rb $APP_HOME
EXPOSE 4567

CMD [ "./run.sh" ]
