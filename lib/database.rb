require 'redis'

class Database

  def initialize
    @redis = Redis.new(host: ENV['REDIS_HOST'], port: 6379, db: 06)
  end

  def save(key, data)
    @redis.set(key, serialize(data))
  end

  def restore(key)
    data = @redis.get(key)
    data ? deserialize(data) : data
  end

  private

  def serialize(data)
    Marshal.dump(data)
  end

  def deserialize(data)
    Marshal.load(data)
  end

end
