/*
 * pci.c
 *
 * Copyright (C) 2004 ICT CAS
 * Author: Lin Wei, ICT CAS
 *   wlin@ict.ac.cn
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 *  THIS  SOFTWARE  IS PROVIDED   ``AS  IS'' AND   ANY  EXPRESS OR IMPLIED
 *  WARRANTIES,   INCLUDING, BUT NOT  LIMITED  TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 *  NO  EVENT  SHALL   THE AUTHOR  BE    LIABLE FOR ANY   DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMITED   TO, PROCUREMENT OF  SUBSTITUTE GOODS  OR SERVICES; LOSS OF
 *  USE, DATA,  OR PROFITS; OR  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN  CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the  GNU General Public License along
 *  with this program; if not, write  to the Free Software Foundation, Inc.,
 *  675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#include <linux/pci.h>
#include <boot_param.h>

extern int ls2h_pcibios_map_irq(struct pci_dev *dev, u8 slot, u8 pin);
extern int rs780e_pcibios_map_irq(struct pci_dev *dev, u8 slot, u8 pin);
extern int ls2h_pcibios_plat_dev_init(struct pci_dev *dev);
extern int rs780e_pcibios_plat_dev_init(struct pci_dev *dev);
int __init pcibios_map_irq(struct pci_dev *dev, u8 slot, u8 pin)
{
	if(board_type == LS2H)
		return ls2h_pcibios_map_irq(dev,slot,pin);
	else
		return rs780e_pcibios_map_irq(dev,slot,pin);
}
int pcibios_plat_dev_init(struct pci_dev *dev)
{
	if(board_type == LS2H)
		return ls2h_pcibios_plat_dev_init(dev);
	else
		return rs780e_pcibios_plat_dev_init(dev);
}
