require 'bundler/setup'

require 'sinatra'
require 'rest-client'
require 'json'
require 'pp'

get "/*" do
    params[:splat].first
end

post "/*" do
    payload = request.body.read
    docker = JSON.parse(payload)
    docker["events"].each do |event|
        next if event["action"] != "push"

        target = event["target"]
        next unless target["url"].include? "/manifests/"

        image = "#{event["request"]["host"]}/#{target["repository"]}:#{target["tag"]}"
        developer = target["repository"].split("/")[0]
        publish_user = "#{event["actor"]["name"]}"
        url = target["url"]
        publish_from = event["request"]["addr"]

        slack = [
            {
                "type" => "section",
                "text" => {
                    "type": "mrkdwn",
                    "text": "*New Developer Image*:\n- #{image}"
                }
            },
            {
                "type" => "context",
                "elements" => [
                    {
                        "type": "mrkdwn",
                        "text": "*Developer*: #{developer}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Published by*: #{publish_user}"
                    }
                ]
            }
        ]

        logger.info "#{publish_user} published #{image} from #{publish_from}: #{url}"
        begin
            resp = RestClient.post(
                    ENV["SLACK_WEBHOOK"],
                    payload: {
                        "blocks" => slack
                    }.to_json,
            )
            logger.error(resp) if resp.code != 200
        rescue Exception => e
            logger.error(e)
        end
    end

    "OK"
end
