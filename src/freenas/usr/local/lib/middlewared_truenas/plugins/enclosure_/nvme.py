from middlewared.service import Service, private


class EnclosureService(Service):

    @private
    def fake_nvme_enclosure(self, id, name, model, count, slot_to_nvd):
        elements = {'Array Device Slot': {}, "has_slot_status": False}
        for slot in range(1, 1 + count):
            device = slot_to_nvd.get(slot, None)

            if device is not None:
                status = "OK"
                value_raw = 16777216
            else:
                status = "Not Installed"
                value_raw = 83886080

            elements['Array Device Slot'].update({
                slot: {
                    "descriptor": f"Disk #{slot}",
                    "status": status,
                    "value": "None",
                    "value_raw": value_raw,
                    "dev": device,
                }
            })

        return [{
            "id": id,
            "name": name,
            "model": model,
            "controller": True,
            "elements": elements,
        }]
