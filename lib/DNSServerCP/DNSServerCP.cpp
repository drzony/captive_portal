#include "DNSServerCP.h"
#include <lwip/def.h>
#include <Arduino.h>

DNSServerCP::DNSServerCP()
{
  _ttl = htonl(DNS_DEFAULT_TTL);
  _errorReplyCode = DNSReplyCode::NonExistentDomain;
  _dnsHeader    = (DNSHeader*) malloc( sizeof(DNSHeader) ) ;
  _dnsQuestion  = (DNSQuestion*) malloc( sizeof(DNSQuestion) ) ;     
  _buffer     = NULL;
  _currentPacketSize = 0;
  _port = 0;
}

bool DNSServerCP::start(const uint16_t &port, const String &domainName,
                     const IPAddress &resolvedIP)
{
  _port = port;
  _buffer = NULL;
  _domainName = domainName;
  _resolvedIP[0] = resolvedIP[0];
  _resolvedIP[1] = resolvedIP[1];
  _resolvedIP[2] = resolvedIP[2];
  _resolvedIP[3] = resolvedIP[3];
  downcaseAndRemoveWwwPrefix(_domainName);
  return _udp.begin(_port) == 1;
}

void DNSServerCP::setErrorReplyCode(const DNSReplyCode &replyCode)
{
  _errorReplyCode = replyCode;
}

void DNSServerCP::setTTL(const uint32_t &ttl)
{
  _ttl = htonl(ttl);
}

void DNSServerCP::stop()
{
  _udp.stop();
  free(_buffer);
  _buffer = NULL;
}

void DNSServerCP::downcaseAndRemoveWwwPrefix(String &domainName)
{
  domainName.toLowerCase();
  domainName.replace("www.", "");
}

void DNSServerCP::processNextRequest()
{
  _currentPacketSize = _udp.parsePacket();
  if (_currentPacketSize)
  {
    // Allocate buffer for the DNS query
    if (_buffer != NULL) 
      free(_buffer);
    _buffer = (unsigned char*)malloc(_currentPacketSize * sizeof(char));
    if (_buffer == NULL) 
      return;

    // Put the packet received in the buffer and get DNS header (beginning of message)
    // and the question
    _udp.read(_buffer, _currentPacketSize);
    memcpy( _dnsHeader, _buffer, DNS_HEADER_SIZE ) ; 
    if ( requestIncludesOnlyOneQuestion() )
    {
      // The QName has a variable length, maximum 255 bytes and is comprised of multiple labels.
      // Each label contains a byte to describe its length and the label itself. The list of 
      // labels terminates with a zero-valued byte. In "github.com", we have two labels "github" & "com"
      // Iterate through the labels and copy them as they come into a single buffer (for simplicity's sake)
      _dnsQuestion->QNameLength = 0 ;
      while ( _buffer[ DNS_HEADER_SIZE + _dnsQuestion->QNameLength ] != 0 )
      {
        memcpy( (void*) &_dnsQuestion->QName[_dnsQuestion->QNameLength], (void*) &_buffer[DNS_HEADER_SIZE + _dnsQuestion->QNameLength], _buffer[DNS_HEADER_SIZE + _dnsQuestion->QNameLength] + 1 ) ;
        _dnsQuestion->QNameLength += _buffer[DNS_HEADER_SIZE + _dnsQuestion->QNameLength] + 1 ; 
      }
      _dnsQuestion->QName[_dnsQuestion->QNameLength] = 0 ; 
      _dnsQuestion->QNameLength++ ;   

      // Copy the QType and QClass 
      memcpy( &_dnsQuestion->QType, (void*) &_buffer[DNS_HEADER_SIZE + _dnsQuestion->QNameLength], sizeof(_dnsQuestion->QType) ) ;
      memcpy( &_dnsQuestion->QClass, (void*) &_buffer[DNS_HEADER_SIZE + _dnsQuestion->QNameLength + sizeof(_dnsQuestion->QType)], sizeof(_dnsQuestion->QClass) ) ;
    }
    
    String parsed_domain = getDomainNameWithoutWwwPrefix();
    Serial.printf("Got domain '%s'\n", parsed_domain.c_str());
    if (_dnsHeader->QR == DNS_QR_QUERY &&
        _dnsHeader->OPCode == DNS_OPCODE_QUERY &&
        requestIncludesOnlyOneQuestion() &&
        (_domainName == "*" || parsed_domain == _domainName)
       )
    {
      const char *domains[] = {
        "msftncsi.com",
        "clients1.google.com",
        "clients2.google.com",
        "clients3.google.com",
        "clients4.google.com",
        "connectivitycheck.android.com",
        "connectivitycheck.gstatic.com",
        "clients.l.google.com",
        "play.googleapis.com",
        NULL
      };
      size_t i = 0;
      bool fake = false;
      while (domains[i]) {
        if (parsed_domain == domains[i]) {
          fake = true;
          break;
        }
        i++;
      }
      if (fake)
      {
        Serial.println("Sending fake");
        unsigned char fakeIP[4] = { _resolvedIP[0], _resolvedIP[1], _resolvedIP[2], (uint8_t)(_resolvedIP[3] + 10)};
        replyWithIP(fakeIP);
      }
      else
      {
        Serial.println("Sending proper");
        replyWithIP(_resolvedIP);
      }
    }
    else if (_dnsHeader->QR == DNS_QR_QUERY)
    {
      replyWithCustomCode();
    }

    free(_buffer);
    _buffer = NULL;
  }
}

bool DNSServerCP::requestIncludesOnlyOneQuestion()
{
  return ntohs(_dnsHeader->QDCount) == 1 &&
         _dnsHeader->ANCount == 0 &&
         _dnsHeader->NSCount == 0 &&
         _dnsHeader->ARCount == 0;
}


String DNSServerCP::getDomainNameWithoutWwwPrefix()
{
  // Error checking : if the buffer containing the DNS request is a null pointer, return an empty domain
  String parsedDomainName = "";
  if (_buffer == NULL) 
    return parsedDomainName;
  
  // Set the start of the domain just after the header (12 bytes). If equal to null character, return an empty domain
  unsigned char *start = _buffer + DNS_OFFSET_DOMAIN_NAME;
  if (*start == 0)
  {
    return parsedDomainName;
  }

  int pos = 0;
  while(true)
  {
    unsigned char labelLength = *(start + pos);
    for(int i = 0; i < labelLength; i++)
    {
      pos++;
      parsedDomainName += (char)*(start + pos);
    }
    pos++;
    if (*(start + pos) == 0)
    {
      downcaseAndRemoveWwwPrefix(parsedDomainName);
      return parsedDomainName;
    }
    else
    {
      parsedDomainName += ".";
    }
  }
}

void DNSServerCP::replyWithIP(unsigned char dest_address[4])
{
  if (_buffer == NULL) return;
  
  _udp.beginPacket(_udp.remoteIP(), _udp.remotePort());
  
  // Change the type of message to a response and set the number of answers equal to 
  // the number of questions in the header
  _dnsHeader->QR      = DNS_QR_RESPONSE;
  _dnsHeader->ANCount = _dnsHeader->QDCount;
  _dnsHeader->QR      = 1;
  _dnsHeader->OPCode  = 0;
  _dnsHeader->AA      = 1;
  _dnsHeader->TC      = 0;
  _dnsHeader->RA      = 0;
  _dnsHeader->Z       = 0;
  _dnsHeader->RCode   = 0;
  _dnsHeader->NSCount = 0;
  _dnsHeader->ARCount = 0;

  _udp.write( (unsigned char*) _dnsHeader, DNS_HEADER_SIZE ) ;

  // Write the question
  _udp.write(_dnsQuestion->QName, _dnsQuestion->QNameLength) ;
  _udp.write( (unsigned char*) &_dnsQuestion->QType, 2 ) ;
  _udp.write( (unsigned char*) &_dnsQuestion->QClass, 2 ) ;

  // Write the answer 
  // Use DNS name compression : instead of repeating the name in this RNAME occurence,
  // set the two MSB of the byte corresponding normally to the length to 1. The following
  // 14 bits must be used to specify the offset of the domain name in the message 
  // (<255 here so the first byte has the 6 LSB at 0) 
  _udp.write((uint8_t) 0xC0); 
  _udp.write((uint8_t) DNS_OFFSET_DOMAIN_NAME);  

  // DNS type A : host address, DNS class IN for INternet, returning an IPv4 address 
  uint16_t answerType = htons(DNS_TYPE_A), answerClass = htons(DNS_CLASS_IN), answerIPv4 = htons(DNS_RDLENGTH_IPV4)  ; 
  _udp.write((unsigned char*) &answerType, 2 );
  _udp.write((unsigned char*) &answerClass, 2 );
  _udp.write((unsigned char*) &_ttl, 4);        // DNS Time To Live
  _udp.write((unsigned char*) &answerIPv4, 2 );
  _udp.write(dest_address, 4); // The IP address to return
  _udp.endPacket();
}

void DNSServerCP::replyWithCustomCode()
{
  if (_buffer == NULL) return;
  _dnsHeader->QR = DNS_QR_RESPONSE;
  _dnsHeader->RCode = (unsigned char)_errorReplyCode;
  _dnsHeader->QDCount = 0;

  _udp.beginPacket(_udp.remoteIP(), _udp.remotePort());
  _udp.write(_buffer, sizeof(DNSHeader));
  _udp.endPacket();
}
