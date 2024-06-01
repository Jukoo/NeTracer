

#if __has_attribute(contructor)
  #define   _ctor   __attribute__((contructor)) 
#else 
  #define   _ctor 
#endif 

 
#if __has_attribute(destructor)
  #define   _dtor   __attribute__((destructor)) 
#else 
  #define   _dtor 
#endif 


#if __has_attribute(nonnull)
  #define   _nn __attribute__((nonnull)) 
  #define   __nn(x) __attribute__((nonnull(x)))  
#else 
  #define   _nn
  #define   __nn 
#endif


