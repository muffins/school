module Decorator
  def initialize(item)
    @item = item
  end
  def method_missing(method, *arguments)
    if @item.respond_to?(method)
      @item.send(method, *arguments)
    else
      super
    end
  end
  def respond_to?(method)
    @item.respond_to?(method)
  end
end

#class MyGem
#  def install
#    "Installing gem"
#  end
#
#  def uninstall
#    "Uninstalling"
#  end
#end
#class GemsonTUF
#  include Decorator
#
#  def install
#    "Decorated " + @item.install
#  end
#end
#
#mygem = MyGem.new
#mygem.install                #"Installing Gem"
#mygem = GemsonTUF.new(mygem) # wrap around existing instance
#mygem.install                # "Decorated Installing Gem"
#mygem.uninstall              # "Uninstalling"
#mygem.class                  # GemsonTUF
#
#class MyGem1
#  def install
#    "Installing Gem"
#  end
#end
#
#module GemsonTUF1
#  def install
#    "Decorated " + super
#  end
#end
#
#mygem1 = MyGem1.new
#mygem1.install # "Installing Gem"
#mygem1.extend(GemsonTUF1)
#mygem1.install # "Decorated Installing Gem"

