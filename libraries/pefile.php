<?

class pefile {
    var $handle; 		// Handle for the file
    var $offset_peheader; 	// Location of PE header
    var $offset_sections;	// Location of Sections table
    var $header;		// PE Header
    var $opth;			// Optional Header
    var $sections;		// Sections

    function open($filename) {
	$this->handle = @fopen($filename, 'rb');
        if ($this->handle === FALSE)
            return FALSE;

        fseek($this->handle, 0x3c);
	$this->offset_peheader = ord(fread($this->handle, 1));
	fseek($this->handle, $this->offset_peheader);
        $value = fread($this->handle,2);
	if ($value != "PE") return FALSE;
	// Get the start of sections
	fseek($this->handle, $this->offset_peheader+0x14);
        $value = ord(fread($this->handle,1));
	$this->offset_sections=$this->offset_peheader+0x18+$value;
	return TRUE;
    }


    private function getheader() {
	fseek($this->handle, $this->offset_peheader+4);
	// 0x00: WORD - Machine - Byte Swapped
	// 0x02: WORD - Number of Sections
	// 0x04: DWORD - Time/Date Stamp
	$this->header=unpack(
	    "vcpu/" .
	    "vsections/" .
	    "Vtimedate/" .
	    "VSymbolTable/" .
	    "VNoOfSymbols/" .
	    "vSizeofOptHeader/" .
	    "vChar"
	    , fread($this->handle,0x14));
	return $this->header;
    }

    function getnosections() {
	fseek($this->handle, $this->offset_peheader+6);
        return dechex(ord(fread($this->handle,1)));
    }

    function getoptheader() {
	// Seek to the Optional Header
	fseek($this->handle, $this->offset_peheader+0x18);
	$this->opth=unpack(
	    "vMagic/" .
	    "CMajorLinkerVersion/" .
	    "CMinorLinkerVersion/" .
	    "VSizeOfCode/" .
	    "VSizeOfInitData/" .
	    "VSizeOfUnInitData/" .
	    "VAddressOfEntryPoint/" .
	    "VBaseOfCode/" .
	    "VBaseOfData/" .
	    "VImageBase/" .
	    "VSectionAlignment/" .
	    "VFileAlignment/" .
	    "vMajorOSVersion/" .
	    "vMinorOSVersion/" .
	    "vMajorImgVersion/" .
	    "vMinorImgVersion/" .
	    "vMajorSubSysVersion/" .
	    "vMinorSubSysVersion/" .
	    "VWin32Version/" .
	    "VSizeofImage/" .
	    "VSizeOfHeaders/" .
	    "VCheckSum/" .
	    "vSubSystem/" .
	    "vDLLChar/" .
	    "VSizeofStackRes/" .
	    "VSizeofStackCom/" .
	    "VSizeofHeapRes/" .
	    "VSizeofHeapCom/" .
	    "VLoaderFlags/" .
	    "VNumberofRvaAndSizes"
	    ,fread($this->handle,0x60));
	return $this->opth;
    }

    function getimports() {
	return "Not Done Yet :)";
    }

    function getexports() {
	return "Not Done Yet :)";
    }

    // Calls each of the functions and builds an array of data
    function parsefile() {
        $data['header']=$this->getheader();
	$data['optheader']=$this->getoptheader();
        for ($x=1; $x<=$this->getnosections(); $x++) {
            $this->sections[$x] = new pesection($x, $this->offset_sections, $this->handle);
        }
	$data['section'] = $this->sections;
	$data['imports']=$this->getimports();
	$data['exports']=$this->getexports();
	// Returns Array of data - for direct access to data.
	return $data;
    }

    function closefile() {
	fclose($this->handle);
	unset($this->handle);
    }

    function getcpu() {
        switch ($this->header['cpu']) {
          case 0x14c:
            $this->header['cpu']="80386 cpu needed";
            break;
          case 0x14d:
            $this->header['cpu']="80486 cpu needed";
            break;
          case 0x14e:
            $this->header['cpu']="80586 cpu needed";
            break;
          case 0x162:
            $this->header['cpu']="R2000, R3000 cpu needed";
            break;
          case 0x163:
            $this->header['cpu']="R6000 cpu needed";
            break;
          case 0x166:
            $this->header['cpu']="R4000 cpu needed";
	    break;
          default:
            $this->header['cpu']="cpu needed is unknown";
	    break;
	}
    }
}

class pesection {

    var $data;	// Section Data

    function __construct($section, $baseoffset, $handle) {
	$offset = $baseoffset+0x28*($section-1);
	fseek($handle, $offset);
	$this->data=unpack(
	    "a8type/" .
	    "VPhyAddressOrVirtualSize/" .
	    "VVirtualAddress/" .
	    "VSizeofRawData/" .
	    "VPointerToRaw/" .
	    "VPointerToReloc/" .
	    "VPointerToLineNo/" .
	    "vNoOfReloc/" .
	    "vNoOfLineNo/" .
	    "VCharacteristics"
	    ,fread($handle,0x30));
//	fseek($handle, $baseoffset+$this->data['PhyAddressOrVirtualSize']);
//	$this->data['md5-notworking']=md5(fread($handle, $this->data['SizeofRawData']));
	return true;
    }    

}
